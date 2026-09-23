"""The single chokepoint for every docker/compose invocation the harness makes.

WHY THIS MODULE EXISTS — a timeout you cannot enforce is a comment.

On 2026-07-27 a `docker compose … up --detach --wait --wait-timeout 401` was left running. It
was still alive on 2026-08-11 — 15 days — reparented to PPid 1, parked in `futex_do_wait`, with
`/proc/<pid>/fd` holding no socket to the daemon at all. It was never blocked on Docker. Its own
`--wait-timeout 401` never fired, and neither did any harness ceiling, because the harness never
had one over it: the launcher died and the compose *plugin* outlived it.

`subprocess.run(argv, timeout=N)` does not prevent this. `docker` is a thin client that forks
`/usr/libexec/docker/cli-plugins/docker-compose` as a CHILD. On `TimeoutExpired`, `subprocess`
kills only the process it spawned — the `docker` wrapper — and the plugin grandchild reparents to
init and keeps running, holding whatever it was doing forever. The containers it already created
stay up, owned by nobody. That is the accumulation engine behind the leaked `rollout_*` projects
and the empty compose networks: not a daemon defect, a client-side supervision defect.

So every docker call goes through `run_docker`, which:

  * runs the client in its OWN session/process group (`start_new_session=True`), so the whole
    tree — wrapper AND plugin — is addressable as one unit;
  * enforces a wall-clock ceiling and, on expiry, signals the process GROUP (SIGTERM, grace,
    then SIGKILL) rather than the single child;
  * takes `hard_s` as a KEYWORD-ONLY argument WITH NO DEFAULT, so a call site added later cannot
    silently inherit "wait forever" — the omission is a TypeError at import-test time, not a
    15-day wedge discovered by `ps`.

What this module deliberately does NOT do: retry, interpret exit codes, or decide whether a
failure is infra. Timeouts surface as `DockerTimeout`, which `sweep()` already catches and files
as an EXCLUDE — never as a clean no-leak (docs/ENV-QUALITY.md SCORE-3). The one exception is
teardown, which passes `swallow_timeout=True`: a `finally` block must not replace the real
exception with a cleanup one.
"""

from __future__ import annotations

import os
import signal
import subprocess

# Grace between SIGTERM and SIGKILL to the process group. Long enough for a compose client to
# unwind and short enough that teardown does not itself become the stall.
_KILL_GRACE_S = 5.0


class DockerTimeout(RuntimeError):
    """A docker/compose invocation exceeded its enforced ceiling and its process group was killed.

    Carries the label and any partial output, because the interesting evidence ("waiting for
    container to be healthy") is usually on the stream that was still open when the axe fell.
    """

    def __init__(self, label: str, argv: list[str], hard_s: float, stdout: str, stderr: str):
        self.label = label
        self.argv = argv
        self.hard_s = hard_s
        self.stdout = stdout
        self.stderr = stderr
        tail = (stderr or stdout or "").strip()[-300:]
        super().__init__(
            f"docker {label!r} exceeded its {hard_s:g}s ceiling and was killed "
            f"(process group SIGTERM->SIGKILL); partial output: {tail!r}"
        )


def docker_endpoint() -> str:
    """The daemon this process talks to — stamped into results so a run is never ambiguous
    about which substrate produced it. `DOCKER_HOST` if set (that is how the ephemeral-VM path
    works), else the local socket."""
    return os.environ.get("DOCKER_HOST") or "local:///var/run/docker.sock"


def run_docker(
    argv: list[str],
    *,
    hard_s: float,
    label: str,
    env: dict | None = None,
    swallow_timeout: bool = False,
) -> subprocess.CompletedProcess:
    """Run a docker/compose command under an ENFORCED wall-clock ceiling.

    `hard_s` is keyword-only and has no default on purpose — see the module docstring.

    On expiry the whole process GROUP is killed (not just the direct child) and `DockerTimeout`
    is raised, unless `swallow_timeout=True`, in which case a `CompletedProcess` with
    returncode -9 is returned. Use the swallowing form ONLY in teardown paths.
    """
    if hard_s <= 0:
        raise ValueError(f"hard_s must be positive, got {hard_s!r} for {label!r}")

    full_env = {**os.environ, **(env or {})} if env else None

    # start_new_session=True => setsid(): the client and every plugin/grandchild it forks share
    # one process group id (== the client's pid), so os.killpg reaches all of them. Without it,
    # killing the client orphans the compose plugin, which is exactly the observed failure.
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
        env=full_env,
    )
    try:
        out, err = proc.communicate(timeout=hard_s)
    except subprocess.TimeoutExpired:
        out, err = _kill_group(proc)
        if swallow_timeout:
            return subprocess.CompletedProcess(argv, -9, out, err)
        raise DockerTimeout(label, argv, hard_s, out, err) from None
    return subprocess.CompletedProcess(argv, proc.returncode, out, err)


def _kill_group(proc: subprocess.Popen) -> tuple[str, str]:
    """SIGTERM the process group, give it a grace period, then SIGKILL. Returns partial output.

    `os.getpgid(proc.pid)` is read BEFORE signalling and guarded: if the client already exited
    between the timeout firing and this call, the pgid lookup raises ProcessLookupError and
    there is nothing left to kill.
    """
    try:
        pgid = os.getpgid(proc.pid)
    except ProcessLookupError:
        pgid = None

    if pgid is not None:
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        out, err = proc.communicate(timeout=_KILL_GRACE_S)
    except subprocess.TimeoutExpired:
        if pgid is not None:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            out, err = proc.communicate(timeout=_KILL_GRACE_S)
        except subprocess.TimeoutExpired:
            # The client itself is unkillable (uninterruptible sleep). Do not block the harness
            # on it; the reaper's job is to notice a project with no live owner.
            out, err = "", ""
    return out or "", err or ""


def orphan_compose_clients() -> list[tuple[int, str]]:
    """Every compose client on this box reparented to init — the wedge signature, as a list of
    (pid, cmdline). Read-only; used by diagnostics and by the harness's own exit check so a run
    that leaves one behind says so instead of leaving it for `ps` to find 15 days later."""
    found: list[tuple[int, str]] = []
    try:
        proc_entries = [d for d in os.listdir("/proc") if d.isdigit()]
    except OSError:
        return found
    for d in proc_entries:
        try:
            with open(f"/proc/{d}/cmdline", "rb") as fh:
                cmd = fh.read().replace(b"\0", b" ").decode(errors="replace").strip()
            if "docker-compose" not in cmd and "docker compose" not in cmd:
                continue
            with open(f"/proc/{d}/status") as fh:
                ppid = next((int(ln.split()[1]) for ln in fh if ln.startswith("PPid:")), -1)
        except (OSError, ValueError, StopIteration):
            continue
        if ppid == 1:
            found.append((int(d), cmd))
    return found
