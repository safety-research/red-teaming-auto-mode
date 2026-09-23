"""The retry loop must not launder a congestion-damaged arm into a clean-looking one.

Retrying a provider abort is right — the trial is a non-observation, so re-running it replaces
nothing. But a retry re-runs `run_trial` with the SAME (case, epoch), so without care it
overwrites the artifacts that proved the abort and leaves no trace that it happened. A corpus
that cannot answer "was this cell clean, or re-rolled six times?" has substituted a silent
success for a visible fault, which is the same failure class as scoring a 529-killed trial as a
clean no-leak (docs/ROLLOUT-REBUILD.md §0: a harness fails by producing a number).

These tests pin the three properties that keep it honest: the attempt count rides every record,
the superseded attempts survive on disk, and they stay invisible to every reader — not just to
`matrix.py`'s two-level glob but to a `Path.rglob` walk too, which is why preservation goes
through `supersede()`'s `.superseded` extension tombstone rather than a subdirectory alone.
"""

from __future__ import annotations

import json
import types

import pytest

from rollout import runner


@pytest.fixture
def sweep(tmp_path, monkeypatch):
    """`_sweep_arms` wired to a tmp corpus and a scriptable `run_trial`, with no clock cost."""
    monkeypatch.setattr(runner, "LOGS_DIR", tmp_path)
    # `envx` is synthetic, so it has no ENV_MAX_TURNS entry and `resolve_max_turns` would raise
    # (deliberately — a real env missing from the table must fail at launch). Declare one.
    monkeypatch.setitem(runner.ENV_MAX_TURNS, "envx", runner.AGENT_MAX_TURNS)
    monkeypatch.setattr(runner, "kit_revision", lambda: "deadbeefcafe")
    monkeypatch.setattr(runner, "docker_endpoint", lambda: "unix:///dev/null")
    slept: list[float] = []
    monkeypatch.setattr(runner.time, "sleep", slept.append)

    def run(outcomes: list[dict], *, arms=("control",), epochs=1, n_agents=1):
        """`outcomes` is consumed one per attempt; each is merged into a written result.json."""
        pending = list(outcomes)
        calls: list[int] = []

        def run_trial(arm, strategy, ci, e, exec_mode, *, max_turns=None, n_agents=1,
                      system_knowledge=False, side_task="exfil"):
            calls.append(len(calls) + 1)
            row = {"env": "envx", "arm": arm, "case_index": ci, "epoch": e,
                   "strategy": strategy, "exec_mode": exec_mode, "n_agents": n_agents,
                   "excluded": False, "exclude_class": None,
                   "side_task_succeeded": False, "automode_blocked": False}
            row.update(pending.pop(0) if pending else {})
            # Mirror the real `run_trial`: resolve the budget, then slug with the RESOLVED
            # value — otherwise this fake writes to a directory `_sweep_arms` will not read.
            slug = runner.config_slug("envx", exec_mode, arm, strategy, n_agents,
                                      max_turns=runner.resolve_max_turns("envx", max_turns))
            d = tmp_path / slug
            d.mkdir(parents=True, exist_ok=True)
            stem = f"case{ci}_ep{e}"
            # Mirror the real writer: it supersedes any prior artifacts for this stem BEFORE
            # writing, then writes a result, a ledger and a stream all on the same stem.
            runner.supersede(d, stem)
            (d / f"{stem}.result.json").write_text(json.dumps(row))
            (d / f"{stem}.ledger.jsonl").write_text('{"blocked": false}\n')
            (d / f"{stem}.stream.jsonl").write_text(f"attempt {len(calls)}\n")
            return row

        results: dict = {}
        runner._sweep_arms(
            types.SimpleNamespace(run_trial=run_trial),
            types.SimpleNamespace(name="envx"),
            list(arms), epochs, (0,), "strat", "single", None, n_agents, results,
        )
        return results, calls, slept

    return run


ABORT = {"excluded": True, "exclude_class": "529_overload", "exclude_reason": "Overloaded"}
CLEAN: dict = {}


def test_attempts_rides_every_record_even_when_nothing_retried(sweep):
    """A field present only on failures is useless to an aggregator: absent must not mean 1."""
    results, calls, _ = sweep([CLEAN])
    assert calls == [1]
    assert results["control"]["n_retried"] == 0
    assert results["control"]["n_retry_attempts"] == 0


def test_a_recovered_trial_still_reports_that_it_was_retried(sweep, tmp_path):
    """The whole point: an absorbed retry is still congestion and must stay visible."""
    results, calls, slept = sweep([ABORT, ABORT, CLEAN])
    assert calls == [1, 2, 3], "should have retried twice then succeeded"

    summary = results["control"]
    assert summary["n_retried"] == 1
    assert summary["n_retry_attempts"] == 2
    assert summary["n_valid"] == 1 and summary["n_excluded"] == 0

    slug = runner.config_slug("envx", "single", "control", "strat", 1,
                              max_turns=runner.AGENT_MAX_TURNS)
    final = json.loads((tmp_path / slug / "case0_ep1.result.json").read_text())
    assert final["attempts"] == 3, "the on-disk record is what matrix.py reads"
    assert final["retry_wait_s"] == round(sum(slept))
    assert final["retry_gave_up"] == ""
    assert final["excluded"] is False


def test_every_superseded_attempt_survives_in_its_own_slot(sweep, tmp_path):
    """EACH aborted attempt is preserved, not just the first.

    `supersede()` is idempotent per run-stamp per stem — correct for two write sites inside one
    trial, wrong for a retried trial, which writes the same stem n times in one process. Relying
    on that guard would archive attempt 1 and let attempts 2..n-1 be overwritten in place, which
    is the very thing it was written to stop. The loop passes a per-attempt slot instead.
    """
    sweep([ABORT, ABORT, ABORT, CLEAN])
    slug = runner.config_slug("envx", "single", "control", "strat", 1,
                              max_turns=runner.AGENT_MAX_TURNS)
    archive = tmp_path / slug / runner.SUPERSEDED_DIR

    slots = sorted(p.name for p in archive.iterdir())
    assert len(slots) == 3, f"one slot per superseded attempt, got {slots}"
    assert all(".attempt" in s for s in slots)

    # Each slot holds that attempt's three artifacts, every one extension-tombstoned.
    for slot in slots:
        names = sorted(p.name for p in (archive / slot).iterdir())
        assert names == ["case0_ep1.ledger.jsonl.superseded",
                         "case0_ep1.result.json.superseded",
                         "case0_ep1.stream.jsonl.superseded"], slot

    # The bytes that proved each abort are intact and DISTINCT — not three copies of one attempt.
    streams = sorted((archive / s / "case0_ep1.stream.jsonl.superseded").read_text()
                     for s in slots)
    assert streams == ["attempt 1\n", "attempt 2\n", "attempt 3\n"]
    first = json.loads((archive / slots[0] / "case0_ep1.result.json.superseded").read_text())
    assert first["exclude_class"] == "529_overload"


def test_archived_attempts_are_invisible_to_both_glob_styles(sweep, tmp_path):
    """A subdirectory alone is not enough: `glob.glob` skips dot-dirs but `Path.rglob` descends
    into any directory, so half the callers would read a retired attempt as a live trial. The
    `.superseded` extension is what actually retires it."""
    sweep([ABORT, ABORT, CLEAN])

    # matrix.py's exact glob — a parked attempt counted here would be the double-count bug.
    assert [p.name for p in sorted(tmp_path.glob("*/*.result.json"))] == ["case0_ep1.result.json"]
    # And the stricter reader: a full recursive walk must also find exactly one live result.
    assert [p.name for p in sorted(tmp_path.rglob("*.result.json"))] == ["case0_ep1.result.json"]
    assert not list(tmp_path.rglob("*.ledger.jsonl.superseded.*")), "no double-tombstoning"


def test_gives_up_on_the_attempt_cap_and_excludes(sweep, monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "ABORT_RETRIES", 2)
    results, calls, _ = sweep([ABORT] * 8)
    assert calls == [1, 2, 3], "1 initial + 2 retries, then give up"

    summary = results["control"]
    assert summary["n_valid"] == 0 and summary["n_excluded"] == 1
    assert summary["n_excluded_transport"] == 1, "still counted as congestion, not hidden"

    slug = runner.config_slug("envx", "single", "control", "strat", 1,
                              max_turns=runner.AGENT_MAX_TURNS)
    final = json.loads((tmp_path / slug / "case0_ep1.result.json").read_text())
    assert final["excluded"] is True
    assert "attempt cap" in final["retry_gave_up"]


def test_retries_zero_disables_retrying_entirely(sweep, monkeypatch):
    """`ROLLOUT_ABORT_RETRIES=0` is the documented escape hatch for qualitative runs — a run
    whose value is one transcript must not have that transcript replaced underneath it."""
    monkeypatch.setattr(runner, "ABORT_RETRIES", 0)
    _, calls, slept = sweep([ABORT, CLEAN])
    assert calls == [1], "no retry at all"
    assert slept == [], "and no backoff wait"


def test_wall_clock_budget_bounds_the_wait_not_the_attempt_count(sweep, monkeypatch):
    """The budget is the real bound; it must stop BEFORE overshooting, never after."""
    monkeypatch.setattr(runner, "ABORT_RETRIES", 999)
    monkeypatch.setattr(runner, "ABORT_BACKOFF_S", 100.0)
    monkeypatch.setattr(runner, "ABORT_BACKOFF_MAX_S", 100.0)
    monkeypatch.setattr(runner, "ABORT_BUDGET_S", 250.0)
    _, calls, slept = sweep([ABORT] * 20)
    assert sum(slept) <= 250.0, "must not overshoot the budget it was given"
    assert len(calls) >= 2, "and must actually have retried before giving up"


def test_a_completed_trial_is_never_retried(sweep):
    """Only non-observations are re-run. A fail_open is a FINDING; re-rolling it is the p-hack."""
    _, calls, _ = sweep([{"excluded": True, "exclude_class": "fail_open"}, CLEAN])
    assert calls == [1]


@pytest.mark.parametrize("attempt", [1, 2, 3, 8])
def test_retry_delay_grows_is_capped_and_is_jittered(attempt, monkeypatch):
    monkeypatch.setattr(runner, "ABORT_BACKOFF_S", 10.0)
    monkeypatch.setattr(runner, "ABORT_BACKOFF_MAX_S", 60.0)
    base = min(10.0 * 2 ** (attempt - 1), 60.0)
    seen = {runner._retry_delay(attempt) for _ in range(50)}
    assert all(base * 0.75 <= d <= base * 1.25 for d in seen)
    # Jitter must actually vary: a deterministic backoff synchronises every session on this box.
    assert len(seen) > 1
