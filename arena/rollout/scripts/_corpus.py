#!/usr/bin/env python3
"""Where a rollout corpus lives — the one place that knows, so a tree can be torn down safely.

A corpus is `<root>/logs/<slug>/case*.{result.json,stream.jsonl,ledger.jsonl}` where `<root>` is a
`rollout/` directory. Every analysis script globs that shape, and each one used to name its own
`<root>` as a literal: `build_sa_transcripts.py` defaulted to `/nonexistent/wt-sa-nopi/rollout`,
`fleet_transcripts.py` to `/nonexistent/wt-fleetbridge/rollout`, `lc3_ceiling_rank.py` to
`/nonexistent/wt-lc3/rollout`, and `walk_trial.py` globbed `/nonexistent/wt-*/rollout`.

That coupled every published number to a per-session worktree. `wt-lc3` was removed on 2026-08-22
with its 955 slugs -- so `lc3_ceiling_rank.py`'s default now points at nothing, and it is the third
tree lost this way (`wt-iter2`, `wt-telemetry-redesign`). Worktrees are meant to be disposable; a
corpus is not. So: corpora are ARCHIVED under `CORPUS_HOME/<tag>/rollout/logs/`, outside any git
work tree, and resolution goes through here.

Order is deliberate -- explicit, then local, then archived, then live worktrees:
  1. `$ROLLOUT_ROOT`  -- you said which; nothing may override you
  2. `./rollout`, `.` -- running from inside a checkout
  3. `$CORPUS_HOME/*/rollout` (default `/nonexistent/corpora`) -- the archive, which OUTLIVES trees
  4. `/nonexistent/wt-*/rollout` -- live worktrees, last, because they are the ephemeral copy

Archived before live matters: after a corpus is archived AND its tree removed, (4) matches nothing
and (3) answers. While both exist they hold the same slugs, and the archive carries the
`PROVENANCE.jsonl` census that says which monitor revision produced each record -- which the tree
does not.

With ONE exception: an archive whose `CAMPAIGN.md` says "LIVE at archive time" is a snapshot of a
tree that was still being written, so it is skipped entirely. Preferring it would make an aggregate
read stale counts for a campaign that is still running -- which is the same class of silent-wrong-
number the archive exists to prevent.
"""
from __future__ import annotations

import glob
import os
from pathlib import Path

CORPUS_HOME = Path(os.environ.get("CORPUS_HOME", "/nonexistent/corpora"))


def _is_live_snapshot(rollout_dir: Path) -> bool:
    """True if this archived corpus declares itself a snapshot of a STILL-RUNNING tree.

    `_gather.py` writes that marker when files appeared under the source during the copy. Such an
    archive is already behind its source and will keep falling behind, so preferring it over the
    live tree makes an aggregate silently read stale counts. Measured on wt-lcboost while its lc3c
    run was going: 365 archived records against 360 in the tree -- diverged in BOTH directions,
    because the runner also reconciles and removes. Skip it until the run finishes and the gather is
    re-run without the marker.
    """
    md = rollout_dir.parent / "CAMPAIGN.md"
    try:
        return "LIVE at archive time" in md.read_text()
    except OSError:
        return False


def roots() -> list[Path]:
    """Every plausible rollout root, best first, de-duplicated, existing only."""
    archived = [p for p in sorted(glob.glob(str(CORPUS_HOME / "*" / "rollout")))
                if not _is_live_snapshot(Path(p))]
    out: list[Path] = []
    for cand in ([os.environ.get("ROLLOUT_ROOT", "")]
                 + ["rollout", "."]
                 + archived
                 + sorted(glob.glob("/nonexistent/wt-*/rollout"))):
        if not cand:
            continue
        p = Path(cand)
        try:
            rp = p.resolve()
        except OSError:
            continue
        if rp.is_dir() and rp not in [o.resolve() for o in out]:
            out.append(p)
    return out


def find_slug_root(pattern: str) -> Path | None:
    """The first root whose `logs/` holds a slug matching `pattern`, or None.

    Used instead of a default literal: a script asks for the shape of corpus it analyses and gets
    wherever that corpus actually is, whether that is a live worktree or the archive.
    """
    for r in roots():
        if glob.glob(str(r / "logs" / pattern)):
            return r
    return None


def require_slug_root(pattern: str, what: str) -> Path:
    """`find_slug_root`, but fail LOUDLY rather than analysing an empty glob.

    A missing corpus used to surface as zero rows -- an empty table, not an error -- which reads as
    "the run produced nothing" instead of "the corpus is not on this disk any more".
    """
    r = find_slug_root(pattern)
    if r is None:
        raise SystemExit(
            f"no corpus found for {what} (looked for logs/{pattern}).\n"
            f"  searched: {', '.join(str(p) for p in roots()) or '(nothing)'}\n"
            f"  set ROLLOUT_ROOT=<the rollout/ dir> or CORPUS_HOME=<archive dir>, or restore the "
            f"corpus from the backup bucket (_siblings/<tree>)."
        )
    return r
