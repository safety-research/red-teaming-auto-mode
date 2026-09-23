#!/usr/bin/env python3
"""Stage MonitorKit into the sandbox image's BUILD CONTEXT.

The sandbox Dockerfile `COPY _monitorkit/ /opt/monitorkit/src/`, but MonitorKit lives in the
`../monitorkit` submodule, OUTSIDE the build context — a Docker COPY cannot reach above its
context. This copies the submodule's `src/monitorkit` package into `sandbox/_monitorkit/monitorkit`
so the build bakes the exact pinned revision. Stdlib-only; run from anywhere.

    python scripts/stage_monitorkit_for_build.py           # stage
    python scripts/stage_monitorkit_for_build.py --clean   # remove the staged copy
"""

from __future__ import annotations

import fcntl
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

_PKG = Path(__file__).resolve().parents[1]          # …/<repo>/rollout
_ROOT = _PKG.parent                                  # …/<repo>
MONITORKIT_SRC = _ROOT / "monitorkit" / "src" / "monitorkit"
STAGE_DIR = _PKG / "sandbox" / "base" / "_monitorkit"   # baked into rollout-base by base/Dockerfile
STAGED = STAGE_DIR / "monitorkit"
STAMP = STAGE_DIR / ".monitorkit_stamp"


def _rev() -> str:
    """The revision label for the staged bytes — honest about the gap it cannot close.

    `git rev-parse HEAD` names a COMMIT; `stage()` copies the WORKING TREE. When those differ the
    stamp would otherwise label modified bytes with a clean SHA, and every `Decision`,
    `stamped_kit_revision` and `SUMMARY.json` downstream would name a revision whose contents were
    never run. The `-dirty` suffix makes that un-quotable instead of invisible; `./check pin`
    refuses it outright rather than reporting it after the campaign.
    """
    mk = _ROOT / "monitorkit"
    r = subprocess.run(["git", "-C", str(mk), "rev-parse", "HEAD"],
                       capture_output=True, text=True)
    rev = r.stdout.strip() or "unknown"
    dirty = subprocess.run(["git", "-C", str(mk), "status", "--porcelain", "--", "src"],
                           capture_output=True, text=True)
    if dirty.stdout.strip():
        rev += "-dirty"
    return rev


def _tree_sha256(root: Path) -> str:
    """A content hash of what was actually staged — the thing a revision label is not.

    Path-and-content, sorted, so it is stable across machines and independent of git state. This
    is the only field in the stamp that answers "were these the bytes?" rather than "which commit
    was checked out when someone ran the script?".
    """
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        h.update(p.relative_to(root).as_posix().encode())
        h.update(b"\0")
        h.update(p.read_bytes())
        h.update(b"\0")
    return h.hexdigest()


def clean() -> None:
    if STAGED.exists():
        shutil.rmtree(STAGED)
    STAMP.unlink(missing_ok=True)


def stage() -> str:
    if not MONITORKIT_SRC.exists():
        raise SystemExit(
            f"MonitorKit source not found at {MONITORKIT_SRC}.\n"
            "Run `git submodule update --init` in the repo root first."
        )
    clean()
    shutil.copytree(MONITORKIT_SRC, STAGED,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    rev = _rev()
    STAMP.write_text(
        f"revision={rev}\nsource={MONITORKIT_SRC}\ntree_sha256={_tree_sha256(STAGED)}\n"
    )
    return rev


#: Lock file for the stage. NOT inside STAGED -- `clean()` rmtrees that, which would drop the
#: file out from under a waiter still holding its descriptor.
LOCK = STAGE_DIR / ".stage.lock"


def is_current() -> bool:
    """Is the staged copy ALREADY this revision, byte for byte?

    `stage()` is `clean()` + `copytree`, so every needless call opens a window where the build
    context does not exist. That window is not theoretical: ROLLOUT_PROJECT_SUFFIX (D-71) isolates
    containers but NOT this shared path, so five parallel shards of one env rmtree'd each other's
    context and 4/4 trials in one shard died `INFRA FAILURE ... No such file or directory:
    investigator.py`. Skipping when nothing changed removes the window in the common case; the
    lock below removes it in the rest.
    """
    if not (STAGED.exists() and STAMP.exists()):
        return False
    try:
        got = dict(ln.split("=", 1) for ln in STAMP.read_text().splitlines() if "=" in ln)
        return got.get("revision") == _rev() and got.get("tree_sha256") == _tree_sha256(STAGED)
    except Exception:            # noqa: BLE001 - an unreadable stamp means "not current"
        return False


def main() -> int:
    # EXCLUSIVE ACROSS PROCESSES. Concurrent shards of one env each call this; without the lock
    # they interleave clean() and copytree() on one shared path. See `is_current`.
    STAGE_DIR.mkdir(parents=True, exist_ok=True)
    with open(LOCK, "w") as _lock:
        fcntl.flock(_lock, fcntl.LOCK_EX)
        if "--clean" in sys.argv[1:]:
            clean()
            print(f"cleaned {STAGED}")
            return 0
        if is_current():
            print(f"staged MonitorKit already current @ {_rev()} -> {STAGED}")
            return 0
        rev = stage()
        print(f"staged MonitorKit @ {rev} -> {STAGED}")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
