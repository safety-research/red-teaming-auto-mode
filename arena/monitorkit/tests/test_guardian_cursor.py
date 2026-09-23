"""`GuardianCursorStore` — the per-session cursor + reconstructed reviewer conversation that
drives the guardian DELTA port (D-75). These test the store's LOGIC in isolation; wiring it
into the review path (the OFF flag, reuse-key computation, advance-on-PARSED) is a later
increment.
"""

from __future__ import annotations

import threading
from pathlib import Path

from monitorkit import hook as H
from monitorkit.guardian import GUARDIAN_FOLLOWUP_REMINDER


def _store(tmp_path: Path, sid: str = "sess") -> H.GuardianCursorStore:
    return H.GuardianCursorStore(str(tmp_path / "cursor"), sid)


def test_first_review_is_full_then_the_next_is_a_delta_from_the_cursor(tmp_path):
    s = _store(tmp_path)
    key = {"m": "x"}
    assert s.plan(s.load(), entry_count=3, reuse_key=key).mode == "full"
    s.advance(
        s.plan(s.load(), 3, key), entry_count=3, reuse_key=key,
        review_prompt="P1", verdict="V1",
    )
    st = s.load()
    assert st.prior_review_count == 1 and st.transcript_entry_count == 3
    plan2 = s.plan(st, entry_count=5, reuse_key=key)
    assert plan2.mode == "delta" and plan2.already_seen == 3


def test_a_reuse_key_change_forces_full(tmp_path):
    # A changed model / instructions / cwd / permissions / parent-history (the reuse key,
    # review_session.rs:158-183) invalidates the reused conversation -> full.
    s = _store(tmp_path)
    s.advance(
        s.plan(s.load(), 3, {"m": "x"}), entry_count=3, reuse_key={"m": "x"},
        review_prompt="P1", verdict="V1",
    )
    assert s.plan(s.load(), entry_count=5, reuse_key={"m": "y"}).mode == "full"


def test_a_rewound_transcript_forces_full(tmp_path):
    # Stored cursor past the current count is the `<=` guard (prompt.rs:135-143): the history
    # was rewritten/shrank, so the delta slice would be nonsense -> full.
    s = _store(tmp_path)
    s.advance(
        s.plan(s.load(), 5, {"m": "x"}), entry_count=5, reuse_key={"m": "x"},
        review_prompt="P1", verdict="V1",
    )
    assert s.plan(s.load(), entry_count=2, reuse_key={"m": "x"}).mode == "full"


def test_the_reminder_is_injected_exactly_once_on_review_two(tmp_path):
    s = _store(tmp_path)
    key = {"m": "x"}
    p1 = s.plan(s.load(), 2, key)
    assert not p1.inject_reminder
    s.advance(p1, entry_count=2, reuse_key=key, review_prompt="P1", verdict="V1")

    p2 = s.plan(s.load(), 2, key)
    assert p2.inject_reminder  # review #2
    s.advance(
        p2, entry_count=2, reuse_key=key, review_prompt="P2", verdict="V2",
        reminder_text="REMIND",
    )

    p3 = s.plan(s.load(), 2, key)
    assert not p3.inject_reminder  # not again

    msgs = s.load().prior_messages
    assert [m["role"] for m in msgs] == ["user", "assistant", "developer", "user", "assistant"]
    assert msgs[2]["text"] == "REMIND"  # the reminder sits between verdict#1 and prompt#2


def test_a_full_review_restarts_the_reconstructed_conversation(tmp_path):
    s = _store(tmp_path)
    s.advance(
        s.plan(s.load(), 2, {"m": "x"}), entry_count=2, reuse_key={"m": "x"},
        review_prompt="P1", verdict="V1",
    )
    full_plan = s.plan(s.load(), 2, {"m": "y"})  # reuse-key change -> full
    assert full_plan.mode == "full"
    s.advance(full_plan, entry_count=2, reuse_key={"m": "y"}, review_prompt="P2", verdict="V2")
    st = s.load()
    assert st.prior_review_count == 1  # restarted, not 2
    assert [m["text"] for m in st.prior_messages] == ["P2", "V2"]  # old turns wiped
    assert st.reminder_injected is False


def test_a_corrupt_file_degrades_to_full_and_never_raises(tmp_path):
    s = _store(tmp_path)
    s.path.parent.mkdir(parents=True, exist_ok=True)
    s.path.write_text("{ not json", encoding="utf-8")
    st = s.load()
    assert st.prior_review_count == 0  # default -> full
    assert s.error is not None  # recorded, not raised
    assert s.plan(st, entry_count=3, reuse_key={"m": "x"}).mode == "full"


def test_state_round_trips_through_a_fresh_store(tmp_path):
    s = _store(tmp_path)
    key = {"m": "x", "cwd": "/w"}
    s.advance(
        s.plan(s.load(), 4, key), entry_count=4, reuse_key=key,
        review_prompt="P1", verdict="V1",
    )
    st = _store(tmp_path).load()  # a fresh process, same session id
    assert st.prior_review_count == 1
    assert st.transcript_entry_count == 4
    assert st.reuse_key == key


def test_advance_is_atomic_under_concurrent_gates(tmp_path):
    # Batched tool calls fire concurrent gate processes on the same session. Without the
    # flock, load-modify-save would lose updates and mis-index the cursor. Ten concurrent
    # advances must all land: count 1 (seed) + 10, and 2 messages appended per advance.
    seed = _store(tmp_path)
    seed.advance(
        seed.plan(seed.load(), 1, {"m": "x"}), entry_count=1, reuse_key={"m": "x"},
        review_prompt="P0", verdict="V0",
    )

    def worker(i: int) -> None:
        store = _store(tmp_path)  # independent handle, as a separate process would have
        plan = H.GuardianReviewPlan("delta", 1, False, ())
        store.advance(
            plan, entry_count=1, reuse_key={"m": "x"},
            review_prompt=f"P{i}", verdict=f"V{i}",
        )

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    final = _store(tmp_path).load()
    assert final.prior_review_count == 11  # no lost updates
    assert len(final.prior_messages) == 2 + 20  # seed's 2 + 10 * (user, assistant)


def test_wrong_typed_but_valid_json_degrades_and_never_raises(tmp_path):
    # H1 (the fail-open the review caught): a syntactically-valid but wrong-typed cursor file
    # must degrade to FULL, never raise — a crashed hook under bypassPermissions is an ALLOW.
    # Covers both load() and advance().
    for bad in (
        '{"prior_review_count": "abc"}',
        '{"last_reviewed_transcript_cursor": {"transcript_entry_count": "zz"}}',
        '{"prior_review_count": 1, "reuse_key": [1, 2, 3]}',
        '{"prior_review_count": 1, "prior_messages": 5}',
    ):
        s = _store(tmp_path)
        s.path.parent.mkdir(parents=True, exist_ok=True)
        s.path.write_text(bad, encoding="utf-8")
        st = s.load()  # must not raise
        assert st.prior_review_count == 0  # default -> full
        assert s.error is not None
        assert s.plan(st, entry_count=3, reuse_key={"m": "x"}).mode == "full"
        s.path.write_text(bad, encoding="utf-8")  # advance must also not raise on the poison
        s.advance(
            H.GuardianReviewPlan("full", 0, False, ()), entry_count=3,
            reuse_key={"m": "x"}, review_prompt="P", verdict="V",
        )


def test_a_tuple_valued_reuse_key_still_yields_delta_after_the_round_trip(tmp_path):
    # H3: a tuple/set-valued reuse key must not spuriously force FULL forever once JSON turns
    # tuples into lists on the stored side — both sides are canonicalised before compare.
    s = _store(tmp_path)
    key = {"roots": ("/w", "/tmp"), "perm": "ro"}
    s.advance(
        s.plan(s.load(), 2, key), entry_count=2, reuse_key=key,
        review_prompt="P1", verdict="V1",
    )
    assert s.plan(s.load(), entry_count=4, reuse_key=key).mode == "delta"


def test_a_moved_prefix_forces_full_even_at_a_grown_count(tmp_path):
    # H2 (the recall gap): a same-or-grown count with a CHANGED already-seen prefix digest
    # (compaction / dropped ephemeral <system-reminder>) must force FULL, or a stale delta would
    # hide genuinely-new actions. This is the faithful surrogate for Codex's history_version.
    s = _store(tmp_path)
    key = {"m": "x"}
    s.advance(
        s.plan(s.load(), 3, key, prefix_digest="AAA"), entry_count=3, reuse_key=key,
        review_prompt="P1", verdict="V1", store_prefix_digest="AAA",
    )
    assert s.plan(s.load(), entry_count=6, reuse_key=key, prefix_digest="BBB").mode == "full"
    assert s.plan(s.load(), entry_count=6, reuse_key=key, prefix_digest="AAA").mode == "delta"


def test_reminder_uses_the_module_constant_when_the_caller_omits_text(tmp_path):
    # M2: reminder_text defaults to the module constant, so the once-only reminder is never
    # silently dropped when a caller honours inject_reminder but passes no text.
    s = _store(tmp_path)
    key = {"m": "x"}
    s.advance(
        s.plan(s.load(), 2, key), entry_count=2, reuse_key=key,
        review_prompt="P1", verdict="V1",
    )
    p2 = s.plan(s.load(), 2, key)
    assert p2.inject_reminder
    s.advance(p2, entry_count=2, reuse_key=key, review_prompt="P2", verdict="V2")  # no text
    dev = [m for m in s.load().prior_messages if m["role"] == "developer"]
    assert len(dev) == 1 and dev[0]["text"] == GUARDIAN_FOLLOWUP_REMINDER


def test_advance_accumulates_across_a_growing_session(tmp_path):
    # REGRESSION for the final-review CRITICAL: advance must NOT reset on a normal delta review.
    # The bug fed advance the ALL-ENTRIES digest for the under-lock recompute, which never
    # matched the shorter stored prefix -> spurious FULL -> the conversation was wiped from #3 on
    # and prior_review_count froze at 1. With the two-digest split (seen digest for the recompute,
    # all-entries digest to store), the count grows 1->2->3 and prior_messages accumulates.
    s = _store(tmp_path)
    key = {"m": "x"}
    # review #1 (full): nothing seen yet; store the digest of all 2 entries as "D2".
    p1 = s.plan(s.load(), 2, key, prefix_digest="")
    s.advance(
        p1, entry_count=2, reuse_key=key, review_prompt="P1", verdict="V1",
        prefix_digest="", store_prefix_digest="D2",
    )
    assert s.load().prior_review_count == 1
    # review #2 (delta): the already-seen prefix is unchanged, so its digest matches stored "D2".
    st = s.load()
    p2 = s.plan(st, 4, key, prefix_digest="D2")
    assert p2.mode == "delta" and p2.inject_reminder
    s.advance(
        p2, entry_count=4, reuse_key=key, review_prompt="P2", verdict="V2",
        prefix_digest="D2", store_prefix_digest="D4",
    )
    assert s.load().prior_review_count == 2  # was frozen at 1 before the fix
    # review #3 (delta): reminder does NOT fire again.
    st2 = s.load()
    p3 = s.plan(st2, 6, key, prefix_digest="D4")
    assert p3.mode == "delta" and not p3.inject_reminder
    s.advance(
        p3, entry_count=6, reuse_key=key, review_prompt="P3", verdict="V3",
        prefix_digest="D4", store_prefix_digest="D6",
    )
    final = s.load()
    assert final.prior_review_count == 3
    assert [m["text"] for m in final.prior_messages] == [
        "P1", "V1", GUARDIAN_FOLLOWUP_REMINDER, "P2", "V2", "P3", "V3",
    ]


def test_a_swallowed_save_error_returns_the_on_disk_state(tmp_path, monkeypatch):
    # L1: if save() swallows an OSError, advance() must return what is actually on disk, not the
    # phantom in-memory increment.
    s = _store(tmp_path)
    s.advance(
        s.plan(s.load(), 1, {"m": "x"}), entry_count=1, reuse_key={"m": "x"},
        review_prompt="P0", verdict="V0",
    )
    before = s.load().prior_review_count  # 1

    def boom(*a, **k):
        raise OSError("boom")

    monkeypatch.setattr(H.os, "replace", boom)
    returned = s.advance(
        H.GuardianReviewPlan("delta", 1, False, ()), entry_count=1, reuse_key={"m": "x"},
        review_prompt="P1", verdict="V1",
    )
    assert returned.prior_review_count == before  # matches disk, not before + 1
    assert s.load().prior_review_count == before
    assert s.error is not None
