"""The guardian's input caps, ported byte-for-byte from openai/codex @ 4642370.

WHY THIS IS A MODULE OF ITS OWN. A reviewer that sees MORE than the reviewer it measures
produces a recall number describing nobody, so the caps are part of the artifact and not an
optimisation. They are also the part of the port most likely to drift, because they are
pure arithmetic with no failing test in production to catch a rounding error. Isolating
them means each function here can be diffed against one named Rust function, and tested
without a model, a clock or a transcript.

THE ARITHMETIC IS BYTES, NOT TOKENS. `APPROX_BYTES_PER_TOKEN = 4` and every "token" here is
`ceil(utf8_bytes / 4)`. Upstream ships no tokenizer on this path and "improving" it with
one would change every cap boundary — a strictly worse port that looks strictly better.

WHERE EACH DEFINITION COMES FROM (paths relative to `codex-rs/`):

| here                                   | upstream                                            |
| -------------------------------------- | --------------------------------------------------- |
| `approx_*`                             | `utils/string/src/truncate.rs:4,71-84`               |
| `GUARDIAN_MAX_*`, `TRUNCATION_TAG`     | `core/src/guardian/mod.rs:53-59`                     |
| `guardian_truncate_text`               | `core/src/guardian/prompt.rs:523-546`                |
| `split_truncation_bounds`              | `core/src/guardian/prompt.rs:548-583`                |
| `truncate_guardian_action_value`       | `core/src/guardian/approval_request.rs:219-254`      |
| `truncate_middle_with_token_budget`    | `utils/string/src/truncate.rs:16-35,37-67`           |
| `formatted_truncate_text`              | `utils/output-truncation/src/lib.rs:12-29`           |
| `check_output_token_budget`            | `core/src/tools/context.rs:410-412`                  |

TWO DIFFERENT TRUNCATORS LIVE HERE, and conflating them is the easiest way to get this
wrong. `guardian_truncate_text` (prompt / action strings) CHARGES ITS MARKER against the
byte budget and emits `<truncated omitted_approx_tokens="N" />`;
`truncate_middle_with_token_budget` (a check's own output) does NOT charge its marker and
emits `…N tokens truncated…`. Both are middle elisions on UTF-8 boundaries. Upstream really
does have both, with those two different markers, and the difference is observable in the
bytes the model reads.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = [
    "APPROX_BYTES_PER_TOKEN",
    "DEFAULT_MAX_OUTPUT_TOKENS",
    "GUARDIAN_MAX_ACTION_STRING_TOKENS",
    "GUARDIAN_MAX_APPROVAL_REASON_TOKENS",
    "GUARDIAN_MAX_MESSAGE_ENTRY_TOKENS",
    "GUARDIAN_MAX_MESSAGE_TRANSCRIPT_TOKENS",
    "GUARDIAN_MAX_TOOL_ENTRY_TOKENS",
    "GUARDIAN_MAX_TOOL_TRANSCRIPT_TOKENS",
    "GUARDIAN_MODEL_TRUNCATION_POLICY",
    "GUARDIAN_OMISSION_NOTE",
    "GUARDIAN_RECENT_ENTRY_LIMIT",
    "TRUNCATION_TAG",
    "TruncationPolicy",
    "approx_bytes_for_tokens",
    "approx_token_count",
    "approx_tokens_from_byte_count",
    "check_output_token_budget",
    "formatted_truncate_text",
    "guardian_truncate_text",
    "split_truncation_bounds",
    "truncate_guardian_action_value",
    "truncate_middle_with_token_budget",
]


# ══════════════════════════════════════════════════════════════════════════════════════
# THE ARITHMETIC — `utils/string/src/truncate.rs:4,71-84`
# ══════════════════════════════════════════════════════════════════════════════════════

APPROX_BYTES_PER_TOKEN = 4


def _len_utf8(text: str) -> int:
    """`str::len()` in Rust: UTF-8 BYTES, not code points.

    The single most dangerous line in this module if it were written as `len(text)`. Python
    strings count code points, so a transcript of CJK or emoji would be capped at three to
    four times upstream's budget and every cap boundary in the port would move.
    """
    return len(text.encode("utf-8"))


def approx_token_count(text: str) -> int:
    """`ceil(utf8_bytes / 4)`."""
    return -(-_len_utf8(text) // APPROX_BYTES_PER_TOKEN)


def approx_bytes_for_tokens(tokens: int) -> int:
    return tokens * APPROX_BYTES_PER_TOKEN


def approx_tokens_from_byte_count(byte_count: int) -> int:
    """`ceil(bytes / 4)`. Distinct from `approx_token_count` only in taking a count."""
    return -(-byte_count // APPROX_BYTES_PER_TOKEN)


# ══════════════════════════════════════════════════════════════════════════════════════
# THE CONSTANTS — `core/src/guardian/mod.rs:53-59`, named exactly as upstream names them
# ══════════════════════════════════════════════════════════════════════════════════════

GUARDIAN_MAX_MESSAGE_TRANSCRIPT_TOKENS = 10_000
GUARDIAN_MAX_TOOL_TRANSCRIPT_TOKENS = 10_000
GUARDIAN_MAX_MESSAGE_ENTRY_TOKENS = 2_000
GUARDIAN_MAX_TOOL_ENTRY_TOKENS = 1_000
GUARDIAN_MAX_ACTION_STRING_TOKENS = 16_000
GUARDIAN_MAX_APPROVAL_REASON_TOKENS = 512
"""The cap on the retry/approval reason printed in the APPROVAL REQUEST block. Current Codex
(52d9218) applies `truncate_text(&reason, TruncationPolicy::Tokens(512))` (`prompt.rs:34,234-236`);
this cap was ADDED after 4642370, where the reason was pushed verbatim. See D-74."""
GUARDIAN_RECENT_ENTRY_LIMIT = 40
TRUNCATION_TAG = "truncated"

GUARDIAN_OMISSION_NOTE = "Some conversation entries were omitted."
"""`prompt.rs:407`. Emitted ONLY when whole entries were DROPPED — never for a middle
elision inside an entry, which the `<truncated …/>` marker already announces in place."""


# ══════════════════════════════════════════════════════════════════════════════════════
# THE SHARED SPLIT — `prompt.rs:548-583`, and `truncate.rs:86-124` minus its char counter
# ══════════════════════════════════════════════════════════════════════════════════════


def split_truncation_bounds(
    content: str, prefix_bytes: int, suffix_bytes: int
) -> tuple[str, str]:
    """The head and tail kept by a middle elision, cut on UTF-8 CHARACTER boundaries.

    Upstream has two copies of this loop — `split_guardian_truncation_bounds` and
    `split_string`, which differ only in that the latter also counts removed CHARACTERS for
    a marker this port never emits (see `truncate_middle_with_token_budget`). One copy here,
    because two copies of an arithmetic helper is how the two truncators drift apart.

    The Rust walks `char_indices` and takes a character into the prefix while its END offset
    fits `prefix_bytes`, then takes the FIRST character whose START offset reaches
    `len - suffix_bytes` as the tail. This walks the UTF-8 bytes instead and finds the same
    two boundaries — the largest boundary `<= prefix_bytes`, and the smallest boundary
    `>= len - suffix_bytes` — because a character end IS a boundary and the boundaries are
    ordered. Character-by-character would be a closer visual diff and is what the
    equivalence test in the suite runs against; it is not what runs here, because a
    multi-megabyte tool result would then cost one `encode()` per character.

    The final clamp is upstream's `if suffix_start < prefix_end { suffix_start = prefix_end }`
    — it is what stops an over-generous suffix budget from re-emitting bytes the prefix
    already carried.
    """
    data = content.encode("utf-8")
    length = len(data)

    prefix_end = min(max(prefix_bytes, 0), length)
    while prefix_end > 0 and prefix_end < length and (data[prefix_end] & 0xC0) == 0x80:
        prefix_end -= 1

    suffix_start = min(max(length - suffix_bytes, 0), length)
    while suffix_start < length and (data[suffix_start] & 0xC0) == 0x80:
        suffix_start += 1

    if suffix_start < prefix_end:
        suffix_start = prefix_end

    return data[:prefix_end].decode("utf-8"), data[suffix_start:].decode("utf-8")


# ══════════════════════════════════════════════════════════════════════════════════════
# TRUNCATOR 1: prompt entries and action strings — `prompt.rs:523-546`
# ══════════════════════════════════════════════════════════════════════════════════════


def guardian_truncate_text(content: str, token_cap: int) -> tuple[str, bool]:
    """Middle-elide `content` to at most `token_cap` approximate tokens. Returns
    `(text, was_truncated)`.

    THE MARKER IS CHARGED against the budget — `available = max_bytes - len(marker)`, split
    into a prefix half (rounded DOWN) and a suffix remainder — so the result never exceeds
    `max_bytes`. That is the opposite of the other truncator in this module and it is not a
    detail: charging it is what makes the per-entry caps compose with the transcript
    budgets, and a port that skipped it would overspend both.

    `N` in the marker counts the bytes removed relative to the CAP (`len - max_bytes`), not
    the bytes actually elided (which is larger by the marker's own length). Upstream's own
    arithmetic, reproduced rather than corrected.

    The `max_bytes <= len(marker)` branch returns the bare marker: at a cap that cannot even
    hold the announcement, the announcement is all the model gets.
    """
    if not content:
        return "", False

    max_bytes = approx_bytes_for_tokens(token_cap)
    length = _len_utf8(content)
    if length <= max_bytes:
        return content, False

    omitted_tokens = approx_tokens_from_byte_count(max(length - max_bytes, 0))
    marker = f'<{TRUNCATION_TAG} omitted_approx_tokens="{omitted_tokens}" />'
    marker_bytes = _len_utf8(marker)
    if max_bytes <= marker_bytes:
        return marker, True

    available_bytes = max_bytes - marker_bytes
    prefix_budget = available_bytes // 2
    suffix_budget = available_bytes - prefix_budget
    prefix, suffix = split_truncation_bounds(content, prefix_budget, suffix_budget)
    return f"{prefix}{marker}{suffix}", True


def truncate_guardian_action_value(value: Any) -> tuple[Any, bool]:
    """`GUARDIAN_MAX_ACTION_STRING_TOKENS` applied to EVERY string in the action JSON.

    Recursive over dicts and lists, and object keys are SORTED on the way through, which is
    where the action document's key order comes from upstream. Numbers, booleans and null
    pass through untouched — including a number long enough to be a payload, which upstream
    also leaves alone.

    Returns the rewritten value and whether ANY string was elided; that boolean is
    `reviewed_action_truncated`, which the prompt builder surfaces beside the rendered
    action exactly as `prompt.rs:67,240` does.
    """
    if isinstance(value, str):
        text, truncated = guardian_truncate_text(value, GUARDIAN_MAX_ACTION_STRING_TOKENS)
        return text, truncated
    if isinstance(value, list):
        truncated = False
        items = []
        for item in value:
            item, item_truncated = truncate_guardian_action_value(item)
            truncated = truncated or item_truncated
            items.append(item)
        return items, truncated
    if isinstance(value, dict):
        truncated = False
        out: dict[Any, Any] = {}
        for key in sorted(value, key=str):
            item, item_truncated = truncate_guardian_action_value(value[key])
            truncated = truncated or item_truncated
            out[key] = item
        return out, truncated
    return value, False


# ══════════════════════════════════════════════════════════════════════════════════════
# TRUNCATOR 2: a check's own output — `truncate.rs:16-67` + `output-truncation/lib.rs:12`
# ══════════════════════════════════════════════════════════════════════════════════════


def truncate_middle_with_token_budget(text: str, max_tokens: int) -> tuple[str, int | None]:
    """Middle-elide to `max_tokens`, marker NOT charged. Returns `(text, original_tokens)`,
    the second `None` when nothing was removed.

    The marker is `…N tokens truncated…` — U+2026 on both sides, upstream's literal.

    ONLY THE TOKEN BRANCH IS PORTED. `truncate_text` also has a BYTES branch
    (`truncate_middle_chars`, marker `…N chars truncated…`), and it is unreachable on the
    path this module serves: `context.rs:416` rebuilds the policy as `Tokens(max_tokens)`
    before truncating, whatever mode the model's catalog policy declares. A model whose
    policy is `{bytes, 10000}` therefore does not get the chars marker — it gets a TOKEN
    budget of `ceil(10000/4) = 2500` (see `check_output_token_budget`) and this marker.
    """
    if not text:
        return "", None

    max_bytes = approx_bytes_for_tokens(max_tokens)
    length = _len_utf8(text)
    if max_tokens > 0 and length <= max_bytes:
        return text, None
    if max_bytes == 0:
        # `truncate_with_byte_estimate`'s zero-budget branch: the whole input is "removed"
        # and the marker is the entire output.
        return f"…{approx_tokens_from_byte_count(length)} tokens truncated…", (
            approx_token_count(text)
        )

    prefix_budget = max_bytes // 2
    suffix_budget = max_bytes - prefix_budget
    prefix, suffix = split_truncation_bounds(text, prefix_budget, suffix_budget)
    marker = f"…{approx_tokens_from_byte_count(length - max_bytes)} tokens truncated…"
    truncated = f"{prefix}{marker}{suffix}"
    if truncated == text:  # pragma: no cover — defensive, mirrors truncate.rs:31
        return truncated, None
    return truncated, approx_token_count(text)


def _line_count(text: str) -> int:
    """Rust's `str::lines().count()`.

    NOT `len(text.splitlines())`: Python also breaks on `\\v`, `\\f`, `\\x1c`-`\\x1e`,
    `\\x85`, `\\u2028` and `\\u2029`, so a tool result carrying a form feed would report a
    different line count from production's for the same bytes.
    """
    if not text:
        return 0
    return text.count("\n") + (0 if text.endswith("\n") else 1)


def formatted_truncate_text(content: str, max_tokens: int) -> str:
    """`formatted_truncate_text` with a `Tokens` policy — what a check's output becomes.

    Under the budget the content is returned UNCHANGED, with no warning line. Over it, the
    two-line header goes in front, verbatim:

        Warning: truncated output (original token count: N)
        Total output lines: L
        <blank>
        <middle-elided text>

    The header is upstream's whole signal to the reviewer that it is looking at a hole, and
    the reviewer's tenant policy reads unverifiable context as grounds to lean conservative
    — so dropping the header would not merely lose bytes, it would move verdicts.
    """
    if _len_utf8(content) <= approx_bytes_for_tokens(max_tokens):
        return content
    original_token_count = approx_token_count(content)
    total_lines = _line_count(content)
    result, _ = truncate_middle_with_token_budget(content, max_tokens)
    return (
        f"Warning: truncated output (original token count: {original_token_count})\n"
        f"Total output lines: {total_lines}\n\n{result}"
    )


# ══════════════════════════════════════════════════════════════════════════════════════
# THE BUDGET A CHECK'S OUTPUT GETS — `context.rs:410-412`, `unified_exec/mod.rs:70,189`
# ══════════════════════════════════════════════════════════════════════════════════════

DEFAULT_MAX_OUTPUT_TOKENS = 10_000
"""`unified_exec/mod.rs:70`, the budget a call that names none receives."""


@dataclass(frozen=True)
class TruncationPolicy:
    """A model catalog's `truncation_policy` — `{mode, limit}`, as `protocol.rs:3338` has it.

    Present as a type rather than a bare number because the mode CHANGES THE ANSWER: the
    same `10000` means 10 000 tokens under `tokens` and 2 500 tokens under `bytes`. A port
    that hard-coded the number would silently be four times more generous than a
    `bytes`-policy deployment.
    """

    mode: str
    limit: int

    def __post_init__(self) -> None:
        if self.mode not in ("tokens", "bytes"):
            raise ValueError(f"truncation policy mode must be tokens or bytes, got {self.mode!r}")

    def token_budget(self) -> int:
        if self.mode == "bytes":
            return approx_tokens_from_byte_count(self.limit)
        return self.limit


GUARDIAN_MODEL_TRUNCATION_POLICY = TruncationPolicy("tokens", 10_000)
"""`models-manager/models.json`: `codex-auto-review` declares `{tokens, 10000}`.

Every current catalog entry but `gpt-5.2` (`{bytes, 10000}` → 2 500 tokens) says the same.
Pinned as the guardian default because the guardian's model is the one that matters here.

Upstream derives this per turn from `turn.model_info` (`tools/context.rs:411`); this port does
not, and `truncate_check_output` has no policy parameter to pass one through. So a study
against `gpt-5.2` would get 10 000 tokens where upstream gives 2 500 — ours showing the
reviewer 4× more. LATENT, not live: neither guardian model this project runs declares
`bytes`. Closing it means threading the policy from the model id, not adding a knob.
"""


def check_output_token_budget(
    requested: int | None = None,
    policy: TruncationPolicy = GUARDIAN_MODEL_TRUNCATION_POLICY,
) -> int:
    """`min(requested or DEFAULT, policy.token_budget())`.

    THE MODEL CAN ONLY LOWER IT. A reviewer that asks for `max_output_tokens: 1000000` gets
    the policy's budget, not its request — which is worth stating because the reviewer's own
    tool schema advertises the parameter without saying so, and a port that honoured the
    request literally would hand our reviewer evidence production's cannot see.
    """
    return min(DEFAULT_MAX_OUTPUT_TOKENS if requested is None else requested, policy.token_budget())
