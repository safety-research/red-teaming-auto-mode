"""What a check's own output becomes before the judge reads it.

The OTHER truncator, and conflating it with `_truncate.truncate` is the easy mistake: that one
charges its marker against the budget and emits `<truncated … />`; this one does not charge it
and emits `…N tokens truncated…`. Upstream has both, with those two markers.

Ported from `codex-rs/utils/string/src/truncate.rs`, `utils/output-truncation/src/lib.rs` and
`core/src/tools/context.rs`. Unused until the guardian gets an `exec_command`, and here now so
both halves of the port can be diffed against one Rust commit.
"""

from dataclasses import dataclass

from auto_mode_eval.monitor._format.guardian.truncate import (
    approx_bytes_for_tokens,
    approx_token_count,
    approx_tokens_from_byte_count,
    split_bounds,
)

DEFAULT_MAX_OUTPUT_TOKENS = 10_000  # the budget a call that names none receives


@dataclass(frozen=True)
class TruncationPolicy:
    """A model catalog's `{mode, limit}`. A type rather than a number because the mode changes
    the answer: `10000` means 10 000 tokens under `tokens` and 2 500 under `bytes`."""

    mode: str
    limit: int

    def __post_init__(self) -> None:
        if self.mode not in ("tokens", "bytes"):
            raise ValueError(f"truncation mode must be tokens or bytes, got {self.mode!r}")

    def token_budget(self) -> int:
        if self.mode == "bytes":
            return approx_tokens_from_byte_count(self.limit)
        return self.limit


GUARDIAN_MODEL_TRUNCATION_POLICY = TruncationPolicy("tokens", 10_000)


def check_output_token_budget(
    requested: int | None = None,
    policy: TruncationPolicy = GUARDIAN_MODEL_TRUNCATION_POLICY,
) -> int:
    """The model can only LOWER it: a reviewer asking for a million tokens gets the policy's
    budget, and honouring the request would hand it evidence production's cannot see."""
    budget = DEFAULT_MAX_OUTPUT_TOKENS if requested is None else requested
    return min(budget, policy.token_budget())


def truncate_middle(text: str, max_tokens: int) -> tuple[str, int | None]:
    """Middle-elide to `max_tokens`, marker NOT charged. Returns `(text, original_tokens)`, the
    second `None` when nothing was removed. The marker is U+2026 on both sides."""
    if not text:
        return "", None
    data = text.encode()
    max_bytes = approx_bytes_for_tokens(max_tokens)
    if max_tokens > 0 and len(data) <= max_bytes:
        return text, None
    if max_bytes == 0:  # zero budget: the marker is the whole output
        elided = approx_tokens_from_byte_count(len(data))
        return f"…{elided} tokens truncated…", approx_token_count(text)

    prefix_budget = max_bytes // 2
    prefix, suffix = split_bounds(data, prefix_budget, max_bytes - prefix_budget)
    marker = f"…{approx_tokens_from_byte_count(len(data) - max_bytes)} tokens truncated…"
    return f"{prefix}{marker}{suffix}", approx_token_count(text)


def _line_count(text: str) -> int:
    """Rust's `str::lines().count()`, NOT `len(splitlines())` — Python also breaks on `\\v`,
    `\\f` and friends, so a result carrying a form feed would report a different count."""
    if not text:
        return 0
    return text.count("\n") + (0 if text.endswith("\n") else 1)


def formatted_truncate(content: str, max_tokens: int) -> str:
    """A check's output as the judge sees it: unchanged under budget, and over it the two-line
    header verbatim in front of the elision.

    The header is the whole signal that the reviewer is looking at a hole, and its tenant policy
    reads unverifiable context as grounds to lean conservative — so dropping it would not merely
    lose bytes, it would move verdicts."""
    if len(content.encode()) <= approx_bytes_for_tokens(max_tokens):
        return content
    truncated, _ = truncate_middle(content, max_tokens)
    return (
        f"Warning: truncated output (original token count: {approx_token_count(content)})\n"
        f"Total output lines: {_line_count(content)}\n\n{truncated}"
    )
