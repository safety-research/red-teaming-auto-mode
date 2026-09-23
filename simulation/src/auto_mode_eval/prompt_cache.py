"""Anthropic prompt caching with a breakpoint we choose, not only the one Inspect writes.

Inspect's provider tags exactly one system block, the last (`anthropic.py:1472`). A prompt
whose *tail* varies per call therefore misses on every request even when the ~28k rulebook in
front of it never moves: an entry is only written at a breakpoint, so none ends at the
rulebook boundary for a later call to hit. `cached_system()` marks a system message as ending
a cacheable prefix, and `install()` patches the provider to honour the mark.

A patch rather than a `@modelapi` subclass so `anthropic/…` keeps working everywhere — a
provider would mean rewriting the model name in every flow spec, and a spec that forgot would
silently lose the cache rather than fail. Pinned to inspect_ai's anthropic provider as of
2026-08-13: a change to `resolve_chat_input`'s signature breaks this loudly.
"""

from typing import Any, TypeAlias, cast

from anthropic.types import MessageParam, TextBlockParam
from anthropic.types.beta import BetaRequestMCPServerURLDefinitionParam
from inspect_ai.model import ChatMessage, ChatMessageSystem, GenerateConfig
from inspect_ai.model._providers.anthropic import AnthropicAPI, ToolParamDef, add_cache_control
from inspect_ai.tool import ToolInfo

# Marks a `ChatMessageSystem` in its `metadata`; presence is the mark, the value is unread.
# Metadata rather than a subclass so the mark survives into the `.eval` log with the message.
CACHE_BREAKPOINT = "cache_breakpoint"

# Anthropic allows four `cache_control` blocks per request and Inspect already spends ALL FOUR
# on the direct API: `request["cache_control"]` (`anthropic.py:460`), `system[-1]` (`:1535`),
# `tools[-1]` (`:1538`) and a message lookback (`:1546`). So a marked block cannot be *added* —
# one has to be given back, which is what `_yield_tools_breakpoint` does. One mark still, and
# rejected here rather than at the API, whose error names the limit and not the caller.
MAX_MARKED = 1

_PATCHED = "_auto_mode_eval_prompt_cache"

ResolvedInput: TypeAlias = tuple[
    list[TextBlockParam] | None,
    list[ToolParamDef],
    list[BetaRequestMCPServerURLDefinitionParam],
    list[MessageParam],
    bool,
]


def cached_system(content: str, **kwargs: Any) -> ChatMessageSystem:
    """A system message whose block ends a cacheable prefix: everything up to and including it
    is written to the cache, so a varying tail behind it stops costing the whole prompt."""
    metadata = {**(kwargs.pop("metadata", None) or {}), CACHE_BREAKPOINT: True}
    return ChatMessageSystem(content=content, metadata=metadata, **kwargs)


def _marked_text(messages: list[ChatMessage]) -> set[str]:
    """The rendered text of every marked system message — empty ones dropped, as the provider
    drops them when it builds `system_param`."""
    marked = set()
    for message in messages:
        is_marked = isinstance(message, ChatMessageSystem) and bool(
            (message.metadata or {}).get(CACHE_BREAKPOINT)
        )
        if is_marked and message.text:
            marked.add(message.text)
    return marked


def _yield_tools_breakpoint(tools: list[ToolParamDef]) -> None:
    """Give back the breakpoint Inspect puts on `tools[-1]`, to pay for ours.

    Anthropic orders the prefix tools -> system -> messages, so the marker on `system[-1]` already
    caches everything behind it, tools included; `tools[-1]` only pays when the system half
    changes and the tools do not. Inside a tool loop — the one place both markers coexist, and
    the one place this used to 400 with `Found 5` — the system half is fixed for the whole loop,
    so it never pays. Costs at most one miss on the tool schemas the first time an arm runs.
    """
    if tools:
        # a `TypedDict` at type level, a plain dict at runtime — the provider set the key here
        cast(dict[str, Any], tools[-1]).pop("cache_control", None)


def install() -> None:
    """Wrap `AnthropicAPI.resolve_chat_input` so marked system blocks get a breakpoint too.

    Global and idempotent. Marks are matched on the block's text, not its index: the provider
    builds `system_param` from `m.text` and skips the empty ones, so positions do not line up
    with `input`. A mark on the block Inspect already tagged (the last system message) is a
    no-op and does not spend the tools breakpoint.
    """
    original = AnthropicAPI.resolve_chat_input
    if getattr(original, _PATCHED, False):
        return

    async def resolve_chat_input(
        self: AnthropicAPI,
        input: list[ChatMessage],
        tools: list[ToolInfo],
        config: GenerateConfig,
    ) -> ResolvedInput:
        resolved = await original(self, input, tools, config)
        system_param, tools_param, _mcp, _messages, cache_prompt = resolved
        marked = _marked_text(input)
        if len(marked) > MAX_MARKED:
            raise ValueError(
                f"{len(marked)} cached_system() messages, at most {MAX_MARKED} fits in "
                "Anthropic's four-breakpoint budget alongside Inspect's own"
            )
        # `cache_prompt` False is the caller (or the model) opting out — respect it
        if not (cache_prompt and system_param):
            return resolved
        added = False
        for block in system_param:
            # re-tagging a block Inspect already tagged is a no-op, and costs nothing to skip
            already = "cache_control" in block
            if block["text"] in marked and not already:
                add_cache_control(block, self.cache_ttl)
                added = True
        if added:
            _yield_tools_breakpoint(tools_param)
        return resolved

    setattr(resolve_chat_input, _PATCHED, original)
    AnthropicAPI.resolve_chat_input = resolve_chat_input  # type: ignore[method-assign]


def uninstall() -> None:
    """Put the provider's own method back — for a test that measures the unpatched baseline."""
    original = getattr(AnthropicAPI.resolve_chat_input, _PATCHED, None)
    if original is not None:
        AnthropicAPI.resolve_chat_input = original
