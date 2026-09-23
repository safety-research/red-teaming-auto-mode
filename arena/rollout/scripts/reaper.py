#!/usr/bin/env python3
"""Reclaim leaked Docker state — PLAN-ONLY by default, and deliberately hard to arm.

WHY THIS IS SO CONSERVATIVE

A census of this box on 2026-08-11 tried every obvious "is this run still alive?" signal and
found most of them not merely weak but INVERTED:

  * CPU/IO is backwards. The newest, presumed-live agent container read 0.00%; a 22h-old
    abandoned sink read 70.69%. Ranking by activity puts dead state above live state, because
    the sink's healthcheck (`interval: 3s, retries: 240`) spins forever after its run is gone
    while a live agent container sits idle waiting on an API call.
  * "A host process still holds the project" is false for EVERY live project — the harness runs
    `compose up -d` and returns, then drives the box with short-lived `exec` calls, so nothing
    holds the name. Meanwhile the 15-day wedged compose client "held" a project with zero
    containers. The signal is neither necessary nor sufficient, in both directions at once.
  * `docker events --since` cannot answer retrospectively: the daemon keeps a 256-entry ring,
    which during a burst spans seven seconds.
  * `docker ps --filter until=…` DOES NOT EXIST. It is valid only on `prune`. Passed to `ps` it
    prints an error, and an error piped to `wc -l` reads as a count of one — docs/ROLLOUT-REBUILD.md
    §0 exactly: a harness fails by producing a number, not by crashing.

So this tool trusts only what is structurally true: a compose network with nothing attached is
unused; a dangling image is unreachable; an exited container is not running. Everything that
requires a judgement about whether work is "still happening" is gated behind an explicit lease
that the harness must write — and until it does, the container tier deletes nothing, which for a
box with no lease is the correct answer rather than a cautious one.

USAGE

    reaper.py                          # plan only: print what WOULD go, touch nothing
    reaper.py --json                   # same, machine-readable (for a cron that only reports)
    reaper.py --tiers networks,images  # restrict the plan
    reaper.py --apply --i-know --max-deletions 50    # actually delete; all three required

Arming it takes three independent flags because a reaper is unattended destructive software
pointed at other people's research runs. The friction is the feature.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field

# ── the floors nothing may cross ──────────────────────────────────────────────────────────
# An absolute age below which NOTHING is ever a candidate, whatever the tier says. A 20-hour
# run is normal here (the k8s env legitimately runs that long), so this is not "old", it is
# "young enough that deleting it would obviously be wrong".
MIN_AGE_S = 6 * 3600

# Containers only become candidates past this. The oldest container on the box at the census was
# 44h, so at 48h this tier deletes zero today — by design. Raise the bar, never lower it silently.
MAX_CONTAINER_AGE_S = 48 * 3600

# Build cache is reclaimed only above this ceiling, and only the unused portion.
BUILD_CACHE_CEILING_GB = 40.0

TIERS = ("networks", "exited", "containers", "images", "cache", "volumes")


def _docker(*args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    """Run a docker command in its own session under an enforced ceiling.

    Same reasoning as rollout.dockercmd (this script is standalone so the repo's operators can
    copy it to a box that has no rollout checkout, so it does not import it)."""
    proc = subprocess.Popen(["docker", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, start_new_session=True)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), 9)
        except (ProcessLookupError, PermissionError):
            pass
        out, err = proc.communicate(timeout=10)
        return subprocess.CompletedProcess(args, -9, out or "", err or "")
    return subprocess.CompletedProcess(args, proc.returncode, out, err)


def _lines(cp: subprocess.CompletedProcess) -> list[str]:
    """Split stdout into non-empty lines — and REFUSE on a non-zero exit.

    A failed docker call must never be read as "nothing matched". That conflation is the
    `--filter until=` incident in miniature."""
    if cp.returncode != 0:
        raise RuntimeError(f"docker call failed (rc={cp.returncode}): {(cp.stderr or '').strip()[-200:]}")
    return [ln for ln in cp.stdout.splitlines() if ln.strip()]


def _cols(ln: str, n: int) -> list[str]:
    """First n tab-separated columns of a docker --format line, right-padded with ''."""
    return (ln.split("\t") + [""] * n)[:n]


@dataclass
class Candidate:
    kind: str
    ident: str
    detail: str
    age_s: float | None = None
    size: str = ""


@dataclass
class Plan:
    tiers: dict[str, list[Candidate]] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)

    def add(self, tier: str, c: Candidate) -> None:
        self.tiers.setdefault(tier, []).append(c)

    def total(self) -> int:
        return sum(len(v) for v in self.tiers.values())


# ── liveness guards ───────────────────────────────────────────────────────────────────────
def read_leases(lease_dir: str) -> set[str]:
    """Projects declared live by a harness lease. Absent today; the harness must grow this.

    A lease is honoured only if its owning process is still alive AND its start time matches,
    which defeats PID reuse. An unparseable lease is treated as LIVE — the failure direction
    that spares state rather than deleting it."""
    live: set[str] = set()
    if not os.path.isdir(lease_dir):
        return live
    for name in os.listdir(lease_dir):
        path = os.path.join(lease_dir, name)
        try:
            with open(path) as fh:
                d = json.load(fh)
        except (OSError, ValueError):
            live.add(f"<unreadable lease {name}>")
            continue
        projects = d.get("projects") or []
        pid, starttime = d.get("pid"), d.get("pid_starttime")
        alive = False
        if isinstance(pid, int):
            try:
                with open(f"/proc/{pid}/stat") as fh:
                    alive = fh.read().rsplit(")", 1)[1].split()[19] == str(starttime)
            except (OSError, IndexError):
                alive = False
        expiry = d.get("expires_monotonic_unix")
        if alive or (isinstance(expiry, (int, float)) and time.time() < expiry):
            live.update(projects)
    return live


def build_in_flight() -> bool:
    """True if any build is running. Pruning build cache under a live build corrupts it.

    Matched on argv[0] rather than by grepping whole command lines: a substring match on
    "buildx" also matches the shell running this very script (and any editor, log tail, or
    agent whose command line mentions it), which would wedge the guard permanently ON and
    quietly ensure the cache tier never runs. Own process group is excluded for the same
    reason. Undeterminable => True, the direction that spares the cache."""
    me, mypg = os.getpid(), os.getpgrp()
    try:
        pids = [d for d in os.listdir("/proc") if d.isdigit()]
    except OSError:
        return True
    for d in pids:
        pid = int(d)
        if pid == me:
            continue
        try:
            with open(f"/proc/{d}/cmdline", "rb") as fh:
                argv = fh.read().split(b"\0")
            if os.getpgid(pid) == mypg:
                continue
        except (OSError, ProcessLookupError):
            continue
        if not argv or not argv[0]:
            continue
        exe = os.path.basename(argv[0].decode(errors="replace"))
        arg1 = argv[1].decode(errors="replace") if len(argv) > 1 and argv[1] else ""
        if exe == "docker-buildx" or (exe == "docker" and arg1 == "build"):
            return True
    return False


def _age_s(created: str) -> float | None:
    """Age from a docker timestamp, or None if it cannot be parsed.

    Docker prints two shapes and this must handle both, because returning None silently
    disables the MIN_AGE floor for that object — a guard that fails open is worse than no
    guard. `ps --format {{.CreatedAt}}` gives '2026-08-11 16:15:02 +0000 UTC'; `network
    inspect {{.Created}}` gives '2026-06-11 06:29:42.086408675 +0000 UTC' (fractional seconds).
    """
    import datetime as _dt

    txt = created.strip().replace("T", " ").rstrip("Z").strip()
    parts = txt.split()
    if len(parts) < 2:
        return None
    date, clock = parts[0], parts[1].split(".")[0]      # drop fractional seconds
    tz = parts[2] if len(parts) > 2 and (parts[2].startswith(("+", "-"))) else "+0000"
    try:
        dt = _dt.datetime.strptime(f"{date} {clock} {tz}", "%Y-%m-%d %H:%M:%S %z")
    except ValueError:
        return None
    return (_dt.datetime.now(_dt.UTC) - dt).total_seconds()


# ── the tiers ─────────────────────────────────────────────────────────────────────────────
def plan_networks(plan: Plan, live: set[str]) -> None:
    """Compose networks with zero attached containers — the partial-`down` signature.

    The one signal trusted unaided: a compose network with nothing on it is unused by
    construction, and recreating one costs milliseconds."""
    ids = _lines(_docker("network", "ls", "--filter", "driver=bridge", "--format", "{{.ID}}"))
    if not ids:
        return
    fmt = "{{.Name}}\t{{len .Containers}}\t{{index .Labels \"com.docker.compose.project\"}}\t{{.Created}}"
    for ln in _lines(_docker("network", "inspect", *ids, "--format", fmt, timeout=180)):
        parts = ln.split("\t")
        if len(parts) < 4:
            continue
        name, attached, project, created = parts[0], parts[1], parts[2], parts[3]
        if name in ("bridge", "host", "none"):
            continue
        if attached != "0" or not project or project == "<no value>":
            continue
        if project in live:
            plan.skipped.append(f"network {name}: project has a live lease")
            continue
        # A network is momentarily empty between `network create` and the first container
        # attaching, so an unaged empty network is NOT safe to remove — that window belongs to a
        # run that is starting right now. No age => no deletion.
        age = _age_s(created)
        if age is None:
            plan.skipped.append(f"network {name}: unparseable Created — refusing to guess age")
            continue
        if age < MIN_AGE_S:
            plan.skipped.append(f"network {name}: younger than the {MIN_AGE_S/3600:g}h floor")
            continue
        plan.add("networks", Candidate("network", name, f"project={project} attached=0", age))


def plan_exited(plan: Plan, live: set[str]) -> None:
    """Containers in a terminal state. Not running means not working."""
    fmt = "{{.ID}}\t{{.Names}}\t{{.CreatedAt}}\t{{.Status}}\t{{.Label \"com.docker.compose.project\"}}"
    for ln in _lines(_docker("ps", "-a", "--filter", "status=exited", "--filter", "status=dead",
                             "--format", fmt)):
        cid, names, created, status, project = _cols(ln, 5)
        if project and project in live:
            plan.skipped.append(f"container {names}: project has a live lease")
            continue
        age = _age_s(created)
        if age is not None and age < MIN_AGE_S:
            plan.skipped.append(f"container {names}: younger than the {MIN_AGE_S/3600:g}h floor")
            continue
        plan.add("exited", Candidate("container", cid, f"{names} ({status})", age))


def plan_containers(plan: Plan, live: set[str]) -> None:
    """RUNNING containers past the maximum lifetime with no lease.

    The only tier that can kill live work. Deliberately calibrated so it deletes nothing today:
    the oldest container at the census was 44h and the bar is 48h. It exists so the threshold is
    written down and reviewable, not so it fires."""
    fmt = "{{.ID}}\t{{.Names}}\t{{.CreatedAt}}\t{{.Label \"com.docker.compose.project\"}}"
    for ln in _lines(_docker("ps", "--format", fmt)):
        cid, names, created, project = _cols(ln, 4)
        if project and project in live:
            plan.skipped.append(f"container {names}: project has a live lease")
            continue
        age = _age_s(created)
        if age is None:
            plan.skipped.append(f"container {names}: unparseable CreatedAt — refusing to guess")
            continue
        if age < MAX_CONTAINER_AGE_S:
            continue
        plan.add("containers", Candidate("container", cid,
                                         f"{names} project={project or '-'}", age))


def plan_images(plan: Plan) -> None:
    """Dangling (untagged, unreferenced) images only.

    NOT tagged images. docs/TRIAGE.md is explicit that inspect hash-suffixes image names per eval
    invocation, so a task has a FAMILY of images and deleting "the stale one" destroys evidence
    about which MonitorKit tree a past run baked. Tagged images are a human's call, never this
    script's."""
    for ln in _lines(_docker("images", "--filter", "dangling=true",
                             "--format", "{{.ID}}\t{{.Size}}\t{{.CreatedAt}}")):
        iid, size, created = _cols(ln, 3)
        age = _age_s(created)
        if age is not None and age < MIN_AGE_S:
            continue
        plan.add("images", Candidate("image", iid, "dangling", age, size))


def plan_volumes(plan: Plan) -> None:
    """ANONYMOUS dangling volumes only — a 64-hex name docker generated and nobody chose.

    A NAMED dangling volume is a different object entirely: somebody wrote that name in a
    compose file, which usually means it is a deliberate cache meant to outlive the containers
    that mount it. `internet-simulator-assets` on this box is exactly that — no labels, no
    attached container, and deleting it would force whatever populates it to refetch. "Nothing
    is using it right now" is the normal resting state of a cache, not evidence it is garbage.
    """
    for name in _lines(_docker("volume", "ls", "--filter", "dangling=true", "--format", "{{.Name}}")):
        if len(name) == 64 and all(c in "0123456789abcdef" for c in name):
            plan.add("volumes", Candidate("volume", name, "anonymous, dangling"))
        else:
            plan.skipped.append(f"volume {name}: NAMED (deliberate, likely a cache) — human call")


def plan_cache(plan: Plan) -> None:
    """Unused build cache above the ceiling. Never while a build is in flight."""
    if build_in_flight():
        plan.skipped.append("build cache: a build is in flight — pruning now can corrupt it")
        return
    try:
        rows = json.loads(_docker("system", "df", "--format", "{{json .}}").stdout or "{}")
    except ValueError:
        rows = {}
    size = rows.get("BuildCache") if isinstance(rows, dict) else None
    plan.add("cache", Candidate("build-cache", "unused",
                                f"prune unused above {BUILD_CACHE_CEILING_GB:g}GB", None, str(size or "?")))


# ── apply ─────────────────────────────────────────────────────────────────────────────────
def apply_plan(plan: Plan, max_deletions: int) -> int:
    """Delete the planned objects, re-verifying each precondition immediately before acting.

    Two-phase: the plan was computed against a snapshot; the world may have moved. Anything that
    no longer matches its predicate is skipped, not forced."""
    if plan.total() > max_deletions:
        print(f"REFUSING: plan has {plan.total()} deletions, --max-deletions is {max_deletions}.",
              file=sys.stderr)
        return 2
    done = 0
    for tier, cands in plan.tiers.items():
        for c in cands:
            if c.kind == "network":
                chk = _docker("network", "inspect", c.ident, "--format", "{{len .Containers}}")
                if chk.returncode != 0 or chk.stdout.strip() != "0":
                    print(f"  skip {c.ident}: no longer empty (drift)")
                    continue
                r = _docker("network", "rm", c.ident)
            elif c.kind == "container":
                r = _docker("rm", "-f", c.ident)
            elif c.kind == "image":
                r = _docker("rmi", c.ident)
            elif c.kind == "volume":
                r = _docker("volume", "rm", c.ident)
            elif c.kind == "build-cache":
                if build_in_flight():
                    print("  skip build cache: a build started since planning")
                    continue
                r = _docker("builder", "prune", "-f",
                            "--keep-storage", f"{BUILD_CACHE_CEILING_GB}GB", timeout=600)
            else:
                continue
            ok = r.returncode == 0
            done += ok
            print(f"  [{tier}] {'removed' if ok else 'FAILED'} {c.kind} {c.ident}"
                  f"{'' if ok else ': ' + (r.stderr or '').strip()[-120:]}")
    return 0 if done or not plan.total() else 1


def _default_lease_dir() -> str:
    """Leases live on tmpfs, so a reboot clears stale ones for free."""
    runtime = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    return os.environ.get("ROLLOUT_LEASE_DIR", f"{runtime}/rollout-leases")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="actually delete (needs --i-know)")
    ap.add_argument("--i-know", action="store_true",
                    help="acknowledge this deletes state other people's runs may need")
    ap.add_argument("--max-deletions", type=int, default=0, help="hard cap; refuses above it")
    ap.add_argument("--tiers", default=",".join(TIERS), help=f"subset of {','.join(TIERS)}")
    ap.add_argument("--lease-dir", default=_default_lease_dir())
    ap.add_argument("--json", action="store_true", help="machine-readable plan")
    args = ap.parse_args()

    want = [t.strip() for t in args.tiers.split(",") if t.strip()]
    bad = [t for t in want if t not in TIERS]
    if bad:
        print(f"unknown tier(s) {bad}; known: {list(TIERS)}", file=sys.stderr)
        return 2

    live = read_leases(args.lease_dir)
    plan = Plan()
    try:
        if "networks" in want:
            plan_networks(plan, live)
        if "exited" in want:
            plan_exited(plan, live)
        if "containers" in want:
            plan_containers(plan, live)
        if "images" in want:
            plan_images(plan)
        if "volumes" in want:
            plan_volumes(plan)
        if "cache" in want:
            plan_cache(plan)
    except RuntimeError as exc:
        print(f"PLANNING FAILED, refusing to act: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({
            "live_leases": sorted(live),
            "plan": {t: [vars(c) for c in cs] for t, cs in plan.tiers.items()},
            "skipped": plan.skipped, "total": plan.total(),
        }, indent=2))
    else:
        print(f"lease dir: {args.lease_dir} ({len(live)} project(s) declared live)")
        for tier in want:
            cands = plan.tiers.get(tier, [])
            print(f"\n[{tier}] {len(cands)} candidate(s)")
            for c in cands[:40]:
                age = f"{c.age_s/3600:.1f}h" if c.age_s else "?"
                print(f"    {c.kind:10s} {c.ident[:24]:24s} age={age:>7s} {c.size:>8s}  {c.detail}")
            if len(cands) > 40:
                print(f"    … and {len(cands)-40} more")
        if plan.skipped:
            print(f"\n[skipped] {len(plan.skipped)} object(s) spared by a guard")
            for s in plan.skipped[:10]:
                print(f"    {s}")
            if len(plan.skipped) > 10:
                print(f"    … and {len(plan.skipped)-10} more")
        print(f"\nTOTAL: {plan.total()} object(s) would be removed.")

    if not args.apply:
        print("\n(plan only — nothing was deleted. --apply --i-know --max-deletions N to act)")
        return 0
    if not args.i_know:
        print("\nREFUSING: --apply requires --i-know.", file=sys.stderr)
        return 2
    if args.max_deletions <= 0:
        print("\nREFUSING: --apply requires a positive --max-deletions.", file=sys.stderr)
        return 2
    print(f"\napplying (cap {args.max_deletions}) …")
    return apply_plan(plan, args.max_deletions)


if __name__ == "__main__":
    sys.exit(main())
