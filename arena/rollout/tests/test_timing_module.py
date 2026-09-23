"""Hermetic unit tests for the additive timing/congestion aggregation (rollout.timing).

Pure functions over a SYNTHETIC ledger + stream — no Docker, no IO, no clock. Pins the
aggregation math (percentiles, usage sums, retry/timeout counts, action-interval waves) and the
graceful-degradation contract (missing/None fields, 0-decision trials -> empty/None, never a
crash). None of these functions may ever feed a harm/leak/block/exclude number.
"""
from __future__ import annotations

import json

from rollout.timing import (
    agent_timing,
    count_api_retries,
    gate_congestion,
    gate_timing,
    latency_stats,
    trial_congestion,
)


# ── latency_stats ──
def test_latency_stats_basic_math():
    s = latency_stats([1.0, 2.0, 3.0, 4.0])
    assert s == {"n": 4, "sum_s": 10.0, "mean_s": 2.5,
                 "p50_s": 2.5, "p95_s": 3.85, "max_s": 4.0}


def test_latency_stats_drops_none_and_bool_and_survives_empty():
    # None dropped; True/False are NOT numbers here (bool is an int subclass).
    s = latency_stats([None, 2.0, True, 4.0])
    assert s["n"] == 2 and s["sum_s"] == 6.0 and s["max_s"] == 4.0
    empty = latency_stats([])
    assert empty == {"n": 0, "sum_s": 0.0, "mean_s": None,
                     "p50_s": None, "p95_s": None, "max_s": None}
    assert latency_stats([7.5])["p95_s"] == 7.5  # single value -> every percentile is it


# ── gate_timing ──
def _dec(latency, usage=None, **extra):
    d = {"latency": latency, "usage": usage or {}}
    d.update(extra)
    return d


def test_gate_timing_none_on_zero_decisions():
    assert gate_timing([]) is None
    assert gate_timing(None) is None


def test_gate_timing_aggregates_latency_usage_and_reviewers():
    decisions = [
        _dec(2.0,
             usage={"input_tokens": 10, "output_tokens": 1, "reasoning_tokens": 0,
                    "cache_read_tokens": 5, "cache_write_tokens": 2},
             s1={"name": "s1", "blocked": False, "attempts": 1,
                 "usage": {"input_tokens": 3, "output_tokens": 1}},
             s2={"name": "s2", "blocked": True, "attempts": 2, "retryable": True,
                 "usage": {"output_tokens": 4}}),
        _dec(4.0,
             usage={"input_tokens": 20, "output_tokens": 2, "reasoning_tokens": 1,
                    "cache_read_tokens": 0, "cache_write_tokens": 0},
             investigator={"name": "agent", "blocked": True, "attempts": 1,
                           "usage": {"input_tokens": 100}}),
    ]
    t = gate_timing(decisions)
    assert t["monitor_latency"] == {"n": 2, "sum_s": 6.0, "mean_s": 3.0,
                                    "p50_s": 3.0, "p95_s": 3.9, "max_s": 4.0}
    assert t["usage_total"] == {"input_tokens": 30, "output_tokens": 3, "reasoning_tokens": 1,
                                "cache_read_tokens": 5, "cache_write_tokens": 2}
    assert t["usage_all_zero"] is False
    # reviewers keyed by their self-reported name; investigator -> "agent".
    assert set(t["per_reviewer"]) == {"s1", "s2", "agent"}
    assert t["per_reviewer"]["s2"]["n_blocked"] == 1
    assert t["per_reviewer"]["s2"]["gate_attempts_total"] == 1  # attempts 2 -> 1 retry
    assert t["per_reviewer"]["s2"]["n_retryable"] == 1
    assert t["per_reviewer"]["s2"]["usage_total"]["output_tokens"] == 4
    assert t["per_reviewer"]["agent"]["usage_total"]["input_tokens"] == 100
    # no per-reviewer latency exposed in the ledger -> the key is simply absent
    assert "latency" not in t["per_reviewer"]["s1"]


def test_gate_timing_flags_all_zero_usage():
    # OpenAI-guardian arms record zeroed usage at source; the flag makes the undercount legible.
    z = {"input_tokens": 0, "output_tokens": 0, "reasoning_tokens": 0,
         "cache_read_tokens": 0, "cache_write_tokens": 0}
    t = gate_timing([_dec(1.5, usage=z), _dec(2.5, usage=z)])
    assert t["usage_all_zero"] is True
    assert t["monitor_latency"]["n"] == 2


def test_gate_timing_tolerates_missing_latency_and_usage():
    t = gate_timing([{"blocked": False}, {"latency": 3.0}])
    assert t["monitor_latency"]["n"] == 1 and t["monitor_latency"]["sum_s"] == 3.0
    assert t["usage_all_zero"] is True and t["per_reviewer"] == {}


# ── gate_congestion ──
def test_gate_congestion_counts_retries_timeouts_infra():
    decisions = [
        {"attempts": 6, "retryable": True},
        {"attempts": 1},
        {"fail_closed_timeout": True, "attempts": 1},
        {"infra_error": True},  # attempts absent -> counts as 1 attempt, 0 retries
    ]
    c = gate_congestion(decisions)
    assert c == {"n_monitor_retries": 5, "n_monitor_retryable": 1,
                 "n_monitor_infra_error": 1, "n_monitor_timeouts": 1}
    assert gate_congestion([]) == {"n_monitor_retries": 0, "n_monitor_retryable": 0,
                                   "n_monitor_infra_error": 0, "n_monitor_timeouts": 0}


# ── count_api_retries (agent stream, Layer 1) ──
def _sys_retry(status, delay_ms, attempt):
    return json.dumps({"type": "system", "subtype": "api_retry",
                       "error_status": status, "retry_delay_ms": delay_ms, "attempt": attempt})


def test_count_api_retries_splits_by_status_and_sums_wait():
    raw = "\n".join([
        _sys_retry(529, 3000, 1),
        _sys_retry(529, 6000, 2),
        _sys_retry(429, 1000, 1),
        json.dumps({"type": "assistant", "message": {"id": "m1", "content": []}}),
    ])
    c = count_api_retries(raw)
    assert c == {"agent_api_retries": 3, "agent_api_retries_529": 2,
                 "agent_api_retries_429": 1, "agent_retry_wait_ms": 10000.0,
                 "agent_max_retry_attempt": 2}


def test_count_api_retries_empty_stream():
    assert count_api_retries("")["agent_api_retries"] == 0
    assert count_api_retries("not json\n{bad")["agent_api_retries"] == 0


# ── agent_timing (terminal result + action-interval waves) ──
def _stream_with_waves():
    """Two assistant messages; the first issues a BATCH of two tool_use in one message (one
    wave), the second issues one. Three tool-result timestamps -> two waves -> one interval."""
    return "\n".join([
        json.dumps({"type": "assistant", "message": {"id": "mA", "content": [
            {"type": "tool_use", "id": "t1"}, {"type": "tool_use", "id": "t2"}]}}),
        json.dumps({"type": "user", "timestamp": "2026-08-11T01:00:00.000Z",
                    "message": {"content": [{"type": "tool_result", "tool_use_id": "t1"}]}}),
        json.dumps({"type": "user", "timestamp": "2026-08-11T01:00:01.000Z",
                    "message": {"content": [{"type": "tool_result", "tool_use_id": "t2"}]}}),
        json.dumps({"type": "assistant", "message": {"id": "mB", "content": [
            {"type": "tool_use", "id": "t3"}]}}),
        json.dumps({"type": "user", "timestamp": "2026-08-11T01:00:05.500Z",
                    "message": {"content": [{"type": "tool_result", "tool_use_id": "t3"}]}}),
        json.dumps({"type": "result", "subtype": "success", "is_error": False,
                    "duration_ms": 8000, "duration_api_ms": 5000, "ttft_ms": 900,
                    "num_turns": 4}),
    ])


def test_agent_timing_waves_and_terminal_fields():
    t = agent_timing(_stream_with_waves())
    assert t["wall_ms"] == 8000 and t["api_ms"] == 5000
    assert t["ttft_ms"] == 900 and t["num_turns"] == 4
    # the batched pair (t1,t2 in message mA) collapses to ONE wave -> 2 waves, 1 interval.
    assert t["n_action_waves"] == 2
    # interval = last-ts-of-waveA (01:00:01.000) -> waveB (01:00:05.500) = 4500 ms.
    assert t["action_interval_ms"]["n"] == 1
    assert t["action_interval_ms"]["max_ms"] == 4500.0


def test_agent_timing_empty_and_no_result():
    t = agent_timing("")
    assert t["wall_ms"] is None and t["num_turns"] is None
    assert t["n_action_waves"] == 0 and t["action_interval_ms"] is None
    # a stream that died before any result event: terminal fields None, waves still counted.
    dying = json.dumps({"type": "user", "timestamp": "2026-08-11T01:00:00.000Z",
                        "message": {"content": [{"type": "tool_result", "tool_use_id": "x"}]}})
    t2 = agent_timing(dying)
    assert t2["wall_ms"] is None and t2["n_action_waves"] == 1


# ── trial_congestion (Layer 1 summed over agents + Layer 2) ──
def test_trial_congestion_merges_agent_and_monitor_layers():
    a0 = _sys_retry(529, 3000, 1)
    a1 = "\n".join([_sys_retry(429, 1000, 3), _sys_retry(429, 1000, 4)])
    c = trial_congestion([a0, a1], [{"attempts": 3}, {"fail_closed_timeout": True}])
    assert c["agent_api_retries"] == 3  # 1 + 2 across the two agents
    assert c["agent_api_retries_529"] == 1 and c["agent_api_retries_429"] == 2
    assert c["agent_max_retry_attempt"] == 4  # max over both agents
    assert c["agent_retry_wait_ms"] == 5000.0
    assert c["n_monitor_retries"] == 2 and c["n_monitor_timeouts"] == 1


def test_trial_congestion_empty_never_crashes():
    c = trial_congestion([], [])
    assert c["agent_api_retries"] == 0 and c["agent_max_retry_attempt"] == 0
    assert c["n_monitor_retries"] == 0
