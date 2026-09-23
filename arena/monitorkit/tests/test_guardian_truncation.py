"""Unit tests for the guardian's input caps — the arithmetic, in isolation.

WHY A FILE OF ITS OWN. These are the functions with no model, no clock and no transcript in
them, and they are also the ones where a wrong answer is invisible: a port that split the
budget the other way, or forgot to charge the marker, or counted code points instead of
UTF-8 bytes, still produces a plausible-looking prompt and a plausible-looking recall
number. So every constant is asserted against upstream's, every boundary is asserted at the
byte, and the character-boundary walk is asserted against a SECOND implementation written
to look like the Rust rather than to be fast.
"""

from __future__ import annotations

import pytest

from monitorkit.guardian_truncation import (
    APPROX_BYTES_PER_TOKEN,
    DEFAULT_MAX_OUTPUT_TOKENS,
    GUARDIAN_MAX_ACTION_STRING_TOKENS,
    GUARDIAN_MAX_MESSAGE_ENTRY_TOKENS,
    GUARDIAN_MAX_MESSAGE_TRANSCRIPT_TOKENS,
    GUARDIAN_MAX_TOOL_ENTRY_TOKENS,
    GUARDIAN_MAX_TOOL_TRANSCRIPT_TOKENS,
    GUARDIAN_MODEL_TRUNCATION_POLICY,
    GUARDIAN_OMISSION_NOTE,
    GUARDIAN_RECENT_ENTRY_LIMIT,
    TRUNCATION_TAG,
    TruncationPolicy,
    approx_bytes_for_tokens,
    approx_token_count,
    approx_tokens_from_byte_count,
    check_output_token_budget,
    formatted_truncate_text,
    guardian_truncate_text,
    split_truncation_bounds,
    truncate_guardian_action_value,
    truncate_middle_with_token_budget,
)


def nbytes(text: str) -> int:
    return len(text.encode("utf-8"))


# ══ the constants ═════════════════════════════════════════════════════════════════════
def test_every_constant_matches_upstream():
    """`guardian/mod.rs:53-59` and `truncate.rs:4`, transcribed. A cap that drifts by a
    factor of four is the difference between a faithful port and a better-informed one, and
    nothing else in the suite would notice."""
    assert APPROX_BYTES_PER_TOKEN == 4
    assert GUARDIAN_MAX_MESSAGE_TRANSCRIPT_TOKENS == 10_000
    assert GUARDIAN_MAX_TOOL_TRANSCRIPT_TOKENS == 10_000
    assert GUARDIAN_MAX_MESSAGE_ENTRY_TOKENS == 2_000
    assert GUARDIAN_MAX_TOOL_ENTRY_TOKENS == 1_000
    assert GUARDIAN_MAX_ACTION_STRING_TOKENS == 16_000
    assert GUARDIAN_RECENT_ENTRY_LIMIT == 40
    assert TRUNCATION_TAG == "truncated"
    assert DEFAULT_MAX_OUTPUT_TOKENS == 10_000
    assert GUARDIAN_OMISSION_NOTE == "Some conversation entries were omitted."


# ══ the arithmetic ════════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("text,tokens", [("", 0), ("a", 1), ("abcd", 1), ("abcde", 2)])
def test_a_token_is_four_bytes_rounded_up(text, tokens):
    assert approx_token_count(text) == tokens
    assert approx_tokens_from_byte_count(nbytes(text)) == tokens


def test_the_count_is_utf8_bytes_and_not_code_points():
    """The single most dangerous line in the module if it were `len(text)`: a CJK
    transcript would be capped at three times upstream's budget and every boundary in the
    port would move, silently and only for non-ASCII."""
    assert approx_token_count("漢") == 1  # 3 bytes
    assert approx_token_count("漢漢") == 2  # 6 bytes, not 1
    assert approx_bytes_for_tokens(3) == 12


# ══ the character-boundary walk ═══════════════════════════════════════════════════════
def reference_split(content: str, prefix_bytes: int, suffix_bytes: int) -> tuple[str, str]:
    """`split_guardian_truncation_bounds` transcribed line for line from `prompt.rs:548-583`.

    Deliberately the slow, literal shape — one step per `char_indices()` iteration — so that
    it can be diffed against the Rust by eye. The shipped implementation walks UTF-8 bytes
    instead, for speed on multi-megabyte tool results; this is the witness that the two
    agree.
    """
    data = content.encode("utf-8")
    length = len(data)
    suffix_start_target = max(length - suffix_bytes, 0)
    prefix_end = 0
    suffix_start = length
    suffix_started = False
    index = 0
    for ch in content:
        width = len(ch.encode("utf-8"))
        char_end = index + width
        if char_end <= prefix_bytes:
            prefix_end = char_end
            index = char_end
            continue
        if index >= suffix_start_target and not suffix_started:
            suffix_start = index
            suffix_started = True
        index = char_end
    if suffix_start < prefix_end:
        suffix_start = prefix_end
    return data[:prefix_end].decode("utf-8"), data[suffix_start:].decode("utf-8")


@pytest.mark.parametrize(
    "content",
    [
        "",
        "a",
        "abcdefghij",
        "héllo wörld",
        "漢字漢字漢字漢字",
        "é\U0001f600ascii\U0001f600",
        "\U0001f600" * 7,
    ],
)
@pytest.mark.parametrize("prefix_bytes", [0, 1, 2, 3, 5, 8, 13, 40])
@pytest.mark.parametrize("suffix_bytes", [0, 1, 3, 7, 40])
def test_the_byte_walk_agrees_with_the_literal_rust_transcription(
    content, prefix_bytes, suffix_bytes
):
    assert split_truncation_bounds(content, prefix_bytes, suffix_bytes) == reference_split(
        content, prefix_bytes, suffix_bytes
    )


def test_an_oversized_suffix_budget_cannot_re_emit_the_prefix():
    """Upstream's final clamp. Without it the two halves overlap and the reviewer is shown
    bytes twice with a marker in between claiming something was removed."""
    prefix, suffix = split_truncation_bounds("abcdef", 4, 100)
    assert prefix == "abcd"
    assert suffix == "ef"


# ══ truncator 1: prompt entries and action strings ════════════════════════════════════
def test_short_content_is_returned_untouched():
    assert guardian_truncate_text("hello", 1_000) == ("hello", False)
    assert guardian_truncate_text("", 1_000) == ("", False)
    assert guardian_truncate_text("a" * 4_000, 1_000) == ("a" * 4_000, False)


def test_the_marker_is_charged_against_the_budget():
    """The property that distinguishes this truncator from the other one. If the marker
    rode free, an entry capped at 1 000 tokens would spend 1 000 tokens PLUS the marker in
    the transcript budget, and the two budgets would overspend by the number of entries."""
    text, truncated = guardian_truncate_text("A" * 5_000, 1_000)
    assert truncated
    assert nbytes(text) == 4_000
    assert '<truncated omitted_approx_tokens="250" />' in text
    assert text.startswith("A") and text.endswith("A")


def test_the_omitted_count_is_relative_to_the_cap_not_to_the_bytes_actually_removed():
    """Upstream computes `ceil((len - max_bytes) / 4)` and ignores that the marker itself
    displaced another 41 bytes. Reproduced rather than corrected: a "better" count here is
    a different prompt from production's."""
    text, _ = guardian_truncate_text("A" * 5_000, 1_000)
    assert 'omitted_approx_tokens="250"' in text  # not 260


def test_the_halves_split_the_remaining_budget_with_the_prefix_rounded_down():
    text, _ = guardian_truncate_text("A" * 200 + "B" * 200, 20)  # 80 bytes, marker is 39
    marker_start = text.index("<truncated")
    marker_end = text.index("/>") + 2
    assert nbytes(text[:marker_start]) == 20  # (80 - 40) // 2
    assert nbytes(text[marker_end:]) == 20
    assert nbytes(text) == 80


def test_a_cap_too_small_for_the_marker_yields_the_bare_marker():
    text, truncated = guardian_truncate_text("A" * 100, 1)
    assert truncated
    assert text == '<truncated omitted_approx_tokens="24" />'


def test_the_result_never_exceeds_the_cap_and_never_splits_a_character():
    """Both halves back off to a character boundary, so a multi-byte cap boundary loses a
    byte or two rather than emitting a broken sequence."""
    text, truncated = guardian_truncate_text("漢" * 5_000, 1_000)
    assert truncated
    assert nbytes(text) <= 4_000
    text.encode("utf-8").decode("utf-8")  # would raise on a split character


# ══ the action walk ═══════════════════════════════════════════════════════════════════
def test_every_string_in_the_action_is_capped_at_its_own_budget():
    """The walk is over the VALUE TREE, not the serialized document: two 64 001-byte
    strings are each capped on their own rather than competing for one budget."""
    big = "x" * (GUARDIAN_MAX_ACTION_STRING_TOKENS * 4 + 1)
    value, truncated = truncate_guardian_action_value(
        {"a": big, "b": {"c": [big, 7, True, None]}, "d": "short"}
    )
    assert truncated
    assert "<truncated" in value["a"]
    assert "<truncated" in value["b"]["c"][0]
    assert value["b"]["c"][1:] == [7, True, None]
    assert value["d"] == "short"


def test_the_walk_sorts_object_keys_at_every_depth():
    """`approval_request.rs:240` — where the action document's key order comes from."""
    value, _ = truncate_guardian_action_value({"z": 1, "a": {"y": 1, "b": 2}})
    assert list(value) == ["a", "z"]
    assert list(value["a"]) == ["b", "y"]


def test_an_action_with_nothing_oversized_reports_no_truncation():
    value, truncated = truncate_guardian_action_value({"cmd": "ls", "n": 3})
    assert value == {"cmd": "ls", "n": 3}
    assert truncated is False


# ══ truncator 2: a check's own output ═════════════════════════════════════════════════
def test_the_check_truncator_does_not_charge_its_marker():
    """The OPPOSITE of the prompt truncator, and upstream really is inconsistent here.
    Porting them the same way would be a near-miss port, which is worse than none."""
    text, original = truncate_middle_with_token_budget("x" * 100, 5)
    assert original == 25
    assert "…20 tokens truncated…" in text
    assert nbytes(text) == 20 + len("…20 tokens truncated…".encode())


def test_the_check_truncator_leaves_short_output_alone():
    assert truncate_middle_with_token_budget("hi", 10) == ("hi", None)
    assert truncate_middle_with_token_budget("", 10) == ("", None)


def test_a_zero_token_budget_yields_the_marker_alone():
    assert truncate_middle_with_token_budget("abcdefgh", 0) == ("…2 tokens truncated…", 2)


def test_the_warning_header_is_upstream_verbatim():
    out = formatted_truncate_text("line\n" * 10, 2)
    assert out.startswith(
        "Warning: truncated output (original token count: 13)\nTotal output lines: 10\n\n"
    )
    assert "tokens truncated…" in out


def test_output_within_budget_carries_no_header():
    assert formatted_truncate_text("small", 10) == "small"


def test_the_line_count_is_rusts_lines_and_not_pythons_splitlines():
    """Python breaks on `\\f`, `\\x85` and `\\u2028`; Rust's `str::lines()` does not. A tool
    result carrying a form feed would otherwise report a line count production never
    prints."""
    text = "a\fb c" + "d" * 100
    assert "Total output lines: 1\n" in formatted_truncate_text(text, 1)


# ══ the budget clamp ══════════════════════════════════════════════════════════════════
def test_the_model_can_lower_the_output_budget_but_never_raise_it():
    assert check_output_token_budget(None) == 10_000
    assert check_output_token_budget(500) == 500
    assert check_output_token_budget(10**9) == 10_000


def test_a_bytes_policy_model_would_get_a_quarter_of_the_budget():
    """`{bytes, 10000}` → `ceil(10000/4)` = 2 500 TOKENS, not 10 000. The clamp is explicit
    in code because the mode changes the answer by a factor of four and the default policy
    hides it."""
    assert GUARDIAN_MODEL_TRUNCATION_POLICY == TruncationPolicy("tokens", 10_000)
    assert check_output_token_budget(None, TruncationPolicy("bytes", 10_000)) == 2_500
    assert check_output_token_budget(9_000, TruncationPolicy("bytes", 10_000)) == 2_500


def test_an_unknown_policy_mode_is_refused():
    with pytest.raises(ValueError):
        TruncationPolicy("characters", 10)
