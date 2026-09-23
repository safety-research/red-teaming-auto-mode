"""Where a corpus lives must not depend on which worktree produced it.

`wt-lc3` was removed on 2026-08-22 with its 955 slug dirs. `lc3_ceiling_rank.py`'s default pointed
at it, so the script's table went EMPTY rather than erroring -- indistinguishable from "the ceiling
arms found nothing". Three trees have now been lost this way (wt-iter2, wt-telemetry-redesign,
wt-lc3). These tests pin the two properties that make a teardown safe: the archive is searched
BEFORE live worktrees, and a missing corpus is loud.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))


@pytest.fixture
def corpus(monkeypatch, tmp_path):
    """_corpus with CORPUS_HOME pointed at a tmp archive and no inherited ROLLOUT_ROOT."""
    monkeypatch.setenv("CORPUS_HOME", str(tmp_path / "corpora"))
    monkeypatch.delenv("ROLLOUT_ROOT", raising=False)
    mod = importlib.import_module("_corpus")
    return importlib.reload(mod)


def _slug(root: Path, slug: str) -> Path:
    d = root / "logs" / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "case0_ep1.result.json").write_text("{}")
    return d


def test_a_missing_corpus_raises_instead_of_returning_nothing(corpus):
    """The lc3 failure mode: an absent corpus must not read as an empty result set."""
    assert corpus.find_slug_root("definitely__not__a__slug*") is None
    with pytest.raises(SystemExit) as e:
        corpus.require_slug_root("definitely__not__a__slug*", "a corpus that is not here")
    msg = str(e.value)
    assert "a corpus that is not here" in msg and "searched" in msg


def test_the_archive_is_searched_before_live_worktrees(corpus, tmp_path, monkeypatch):
    """A tree is disposable; a corpus is not. So the archive must win, or `git worktree remove`
    silently changes which episodes an analysis reads."""
    archive = tmp_path / "corpora" / "sanopi" / "rollout"
    live = tmp_path / "wt-live" / "rollout"
    _slug(archive, "leak_credentials__single__control__cg_p4m4sa_nopi__x")
    _slug(live, "leak_credentials__single__control__cg_p4m4sa_nopi__x")
    monkeypatch.setattr(corpus, "CORPUS_HOME", tmp_path / "corpora")
    monkeypatch.setattr(corpus.glob, "glob", lambda pat: (
        [str(archive)] if "corpora" in pat else [str(live)] if "wt-" in pat else []))
    roots = [str(r) for r in corpus.roots()]
    assert str(archive) in roots and str(live) in roots
    assert roots.index(str(archive)) < roots.index(str(live)), roots


def test_rollout_root_wins_over_everything(corpus, tmp_path, monkeypatch):
    explicit = tmp_path / "explicit" / "rollout"
    _slug(explicit, "leak_credentials__single__x")
    monkeypatch.setenv("ROLLOUT_ROOT", str(explicit))
    mod = importlib.reload(corpus)
    assert str(mod.roots()[0]) == str(explicit)


def test_resolution_is_family_aware(corpus, tmp_path, monkeypatch):
    """Two campaigns share the `single` slug shape and differ only in the cg_<FAMILY>_ segment.

    A looser pattern (`leak_credentials__single__*`) matched the leakboost corpus before the
    single-action one, i.e. it would have built the published single-action payload out of another
    study's episodes. The selector has to carry the family.

    `roots` is stubbed rather than `glob`: find_slug_root globs a SECOND time to test each root for
    the slug, and a blunt glob stub intercepts that inner call too, making every pattern match and
    the test pass vacuously. (It did, the first time.) Stub the root list, exercise the real match.
    """
    sa = tmp_path / "corpora" / "a_sa" / "rollout"
    boost = tmp_path / "corpora" / "b_boost" / "rollout"
    _slug(sa, "leak_credentials__single__control__cg_p4m4sa_nopi__x")
    _slug(boost, "leak_credentials__single__control__cg_leakboost_nopi__x")
    monkeypatch.setattr(corpus, "roots", lambda: [sa, boost])   # sa sorts first, so a loose
    assert corpus.find_slug_root("*single*cg_p4m4sa_*") == sa   # pattern would always pick sa
    assert corpus.find_slug_root("*single*cg_leakboost_*") == boost
    # and the loose pattern really is ambiguous -- it takes whichever root comes first
    assert corpus.find_slug_root("leak_credentials__single__*") == sa


def test_a_live_snapshot_archive_is_skipped(corpus, tmp_path, monkeypatch):
    """An archive of a STILL-RUNNING tree must not shadow the tree.

    The archive is preferred over live worktrees so a trial id keeps resolving after
    `git worktree remove`. But if the tree is still being written, the archive is already behind and
    keeps falling behind -- measured on wt-lcboost mid-run: 365 archived records vs 360 in the tree,
    diverged in BOTH directions because the runner reconciles and removes too. Preferring it there
    makes an aggregate silently read stale counts for a live campaign.
    """
    finished = tmp_path / "corpora" / "a_done" / "rollout"
    live = tmp_path / "corpora" / "b_live" / "rollout"
    for r in (finished, live):
        _slug(r, "leak_credentials__single__control__cg_x_y__z")
    (finished.parent / "CAMPAIGN.md").write_text("# corpus a_done\n\n- slug dirs: **1**\n")
    (live.parent / "CAMPAIGN.md").write_text(
        "# corpus b_live\n\n- **LIVE at archive time**: a run was writing into it.\n")
    monkeypatch.setattr(corpus, "CORPUS_HOME", tmp_path / "corpora")
    monkeypatch.setattr(corpus.glob, "glob", lambda pat: (
        sorted([str(finished), str(live)]) if "corpora" in pat else []))
    roots = [str(r) for r in corpus.roots()]
    assert str(finished) in roots, "a finished archive must still be searched"
    assert str(live) not in roots, "a LIVE-snapshot archive must be skipped, not preferred"


def test_a_finished_archive_still_beats_a_live_worktree(corpus, tmp_path, monkeypatch):
    """The other half: skipping LIVE snapshots must not have disabled the archive preference."""
    archive = tmp_path / "corpora" / "done" / "rollout"
    tree = tmp_path / "wt-x" / "rollout"
    for r in (archive, tree):
        _slug(r, "leak_credentials__single__control__cg_x_y__z")
    (archive.parent / "CAMPAIGN.md").write_text("# corpus done\n")
    monkeypatch.setattr(corpus, "CORPUS_HOME", tmp_path / "corpora")
    monkeypatch.setattr(corpus.glob, "glob", lambda pat: (
        [str(archive)] if "corpora" in pat else [str(tree)] if "wt-" in pat else []))
    roots = [str(r) for r in corpus.roots()]
    assert roots.index(str(archive)) < roots.index(str(tree))
