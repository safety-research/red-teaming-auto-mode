"""Hermetic unit tests for non-destructive re-runs (no Docker / agent / monitor).

Locks the property that a re-run of a configuration cannot silently destroy the previous run's
evidence:

  * a prior trial's artifacts are MOVED aside, not overwritten;
  * archived artifacts are tombstoned so no extension-keyed glob reads them as live data;
  * the archive is idempotent within one process, and per-process ordered;
  * a first run (nothing to supersede) is a no-op, and adjacent epochs are not collateral.

Why it exists. A config directory is keyed by ``config_slug`` and a trial by ``case{i}_ep{n}``, so
re-running a configuration writes over the previous run's ledger, streams and result IN PLACE. The
one env's s2 cell was analysed at 00:57, re-run at 01:25, and analysed again at 01:58; the
second analysis read different bytes at the same path, and the two analysis notes
and ``ifs-recall-gap.md`` now reach opposite conclusions with no way to recover the earlier run.
Nothing crashed and a number was produced — ``docs/ROLLOUT-REBUILD.md`` Sec.0 — so the guard has to
be a test, not a convention.

The tombstone is tested against BOTH glob styles on purpose: ``glob.glob`` skips dot-prefixed
directories and ``Path.rglob`` does not, so a hidden directory alone would still be read by half the
callers in this tree. The extension suffix is what actually makes a retired trial unreadable as live.
"""
from __future__ import annotations

import glob as globmod
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from rollout.runner import SUPERSEDED_DIR, SUPERSEDED_SUFFIX, supersede  # noqa: E402


def _trial(d: Path, stem: str, marker: str) -> None:
    """The three artifacts a real trial leaves behind, plus a per-agent stream."""
    (d / f"{stem}.result.json").write_text(json.dumps({"run": marker}))
    (d / f"{stem}.ledger.jsonl").write_text(json.dumps({"run": marker}) + "\n")
    (d / f"{stem}.stream.jsonl").write_text(marker)
    (d / f"{stem}.agent0.stream.jsonl").write_text(marker)


def test_first_run_has_nothing_to_supersede(tmp_path: Path) -> None:
    assert supersede(tmp_path, "case0_ep1") is None
    assert not (tmp_path / SUPERSEDED_DIR).exists()


def test_prior_run_is_moved_not_overwritten(tmp_path: Path) -> None:
    _trial(tmp_path, "case0_ep1", "first")
    dest = supersede(tmp_path, "case0_ep1")

    assert dest is not None
    assert not (tmp_path / "case0_ep1.result.json").exists(), "the live path must be clear"
    archived = sorted(p.name for p in dest.iterdir())
    assert archived == [
        "case0_ep1.agent0.stream.jsonl" + SUPERSEDED_SUFFIX,
        "case0_ep1.ledger.jsonl" + SUPERSEDED_SUFFIX,
        "case0_ep1.result.json" + SUPERSEDED_SUFFIX,
        "case0_ep1.stream.jsonl" + SUPERSEDED_SUFFIX,
    ]
    kept = json.loads((dest / ("case0_ep1.result.json" + SUPERSEDED_SUFFIX)).read_text())
    assert kept == {"run": "first"}, "the previous run's bytes must survive verbatim"


def test_archived_artifacts_are_invisible_to_both_glob_styles(tmp_path: Path) -> None:
    """The regression that matters: a superseded trial must not re-enter a measurement."""
    _trial(tmp_path, "case0_ep1", "first")
    supersede(tmp_path, "case0_ep1")
    _trial(tmp_path, "case0_ep1", "second")  # the re-run writes fresh artifacts at the live path

    by_glob = globmod.glob(str(tmp_path / "**" / "*.result.json"), recursive=True)
    by_rglob = list(tmp_path.rglob("*.result.json"))
    assert len(by_glob) == 1, f"glob.glob saw a superseded trial: {by_glob}"
    assert len(by_rglob) == 1, f"Path.rglob saw a superseded trial: {by_rglob}"
    assert json.loads(Path(by_glob[0]).read_text()) == {"run": "second"}

    # Asserted as "nothing matched lives in the archive" rather than a count: a trial writes a
    # variable number of stream files (one per agent), so a count would encode the fleet size.
    for pattern in ("*.result.json", "*.ledger.jsonl", "*.stream.jsonl"):
        for hit in tmp_path.rglob(pattern):
            assert SUPERSEDED_DIR not in hit.parts, f"{pattern} matched an archived file: {hit}"
        assert list(tmp_path.glob(pattern)), f"{pattern} should still match the live re-run"

    # ...and still findable on purpose
    assert len(list(tmp_path.rglob("*" + SUPERSEDED_SUFFIX))) == 4


def test_supersede_is_idempotent_within_one_run(tmp_path: Path) -> None:
    """Calling twice for one stem must not archive this run's own fresh writes."""
    _trial(tmp_path, "case0_ep1", "first")
    first = supersede(tmp_path, "case0_ep1")
    _trial(tmp_path, "case0_ep1", "second")
    second = supersede(tmp_path, "case0_ep1")

    assert first == second
    assert json.loads((tmp_path / "case0_ep1.result.json").read_text()) == {"run": "second"}, \
        "the live artifacts of the current run must be left alone"
    assert len(list(first.iterdir())) == 4, "only the first run's four files are archived"


def test_only_the_named_stem_moves(tmp_path: Path) -> None:
    """A re-run of one epoch must not disturb its neighbours — including ep10 vs ep1."""
    _trial(tmp_path, "case0_ep1", "one")
    _trial(tmp_path, "case0_ep2", "two")
    _trial(tmp_path, "case0_ep10", "ten")

    supersede(tmp_path, "case0_ep1")

    assert not (tmp_path / "case0_ep1.result.json").exists()
    assert json.loads((tmp_path / "case0_ep2.result.json").read_text()) == {"run": "two"}
    assert json.loads((tmp_path / "case0_ep10.result.json").read_text()) == {"run": "ten"}, \
        "case0_ep1.* must not glob-match case0_ep10.*"


def test_summary_is_superseded_too(tmp_path: Path) -> None:
    """SUMMARY.json carries leak_rate, so it has the same hazard as a trial."""
    (tmp_path / "SUMMARY.json").write_text(json.dumps({"leak_rate": 1.0}))
    dest = supersede(tmp_path, "SUMMARY")

    assert dest is not None
    assert not (tmp_path / "SUMMARY.json").exists()
    kept = json.loads((dest / ("SUMMARY.json" + SUPERSEDED_SUFFIX)).read_text())
    assert kept == {"leak_rate": 1.0}


def test_directories_are_never_moved(tmp_path: Path) -> None:
    """Only files are artifacts; a stray directory sharing the prefix must be left in place."""
    _trial(tmp_path, "case0_ep1", "first")
    (tmp_path / "case0_ep1.d").mkdir()

    supersede(tmp_path, "case0_ep1")

    assert (tmp_path / "case0_ep1.d").is_dir()


@pytest.mark.parametrize("stem", ["case0_ep1", "SUMMARY"])
def test_archive_is_grouped_under_one_run_stamp(tmp_path: Path, stem: str) -> None:
    """Everything one invocation retires lands together, so the trail is orderable."""
    _trial(tmp_path, "case0_ep1", "first")
    (tmp_path / "SUMMARY.json").write_text("{}")

    supersede(tmp_path, "case0_ep1")
    dest = supersede(tmp_path, "SUMMARY")

    stamps = list((tmp_path / SUPERSEDED_DIR).iterdir())
    assert len(stamps) == 1, "one archive directory per process invocation"
    assert dest == stamps[0]
