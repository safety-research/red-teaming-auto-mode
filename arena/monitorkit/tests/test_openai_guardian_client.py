"""Unit tests for the OpenAI (Responses API) guardian provider client — the FAITHFUL reviewer.

The collaborator is the TRANSPORT — the `responses.create(**kwargs)` surface — injected as a
constructor argument, so every test drives the real conversion code with a scripted stub.
Nothing is patched, no socket is opened, no key is needed. The failure modes worth testing are
exactly the ones invisible unless the request and reply are inspected as data: the `developer`
role folded when it must NOT be, a tool call dropped, truncation inferred from text, the
reviewer's own argument bytes normalised away.
"""

from __future__ import annotations

import json

import pytest

from monitorkit import Usage
from monitorkit.cascade import ConfigurationError
from monitorkit.guardian import ARGUMENTS_PARSE_ERROR, EXEC_COMMAND_TOOL, GuardianReply
from monitorkit.guardian_client import (
    DEFAULT_OPENAI_MODEL,
    DEFAULT_OPENAI_REASONING_EFFORT,
    OUTPUT_SCHEMA_NAME,
    OUTPUT_SCHEMA_STRICT,
    OpenAIGuardianClient,
    build_openai_client,
    codex_forced_reasoning_effort,
    openai_input_items,
    openai_tools,
    reply_from_openai_response,
)

MODEL = "gpt-5.6-luna"


# ── Responses-API-shaped stubs ─────────────────────────────────────────────────────────
class Item:
    """One `output` item (a `function_call` or a `message`), in the SDK's attribute shape."""

    def __init__(self, type: str, **fields: object) -> None:
        self.type = type
        for name, value in fields.items():
            setattr(self, name, value)


class Details:
    def __init__(self, **fields: object) -> None:
        for name, value in fields.items():
            setattr(self, name, value)


class Resp:
    """One provider response."""

    def __init__(
        self,
        *output: Item,
        output_text: str = "",
        status: str = "completed",
        incomplete_details: Details | None = None,
        usage: Details | None = None,
    ) -> None:
        self.output = list(output)
        self.output_text = output_text
        self.status = status
        self.incomplete_details = incomplete_details
        self.usage = usage


def function_call(call_id: str, name: str, arguments: str) -> Item:
    return Item("function_call", call_id=call_id, name=name, arguments=arguments)


class StubTransport:
    """A scripted `responses.create`. Raises on an unscripted call; records every request."""

    def __init__(self, *script: Resp) -> None:
        self.script = list(script)
        self.calls: list[dict] = []
        self.responses = self

    def create(self, **kwargs) -> Resp:
        self.calls.append(kwargs)
        if len(self.calls) > len(self.script):
            raise AssertionError(f"provider call {len(self.calls)} was not scripted")
        return self.script[len(self.calls) - 1]


# ── the reasoning-effort rule ──────────────────────────────────────────────────────────
def test_reasoning_effort_forces_low_when_supported():
    assert codex_forced_reasoning_effort(("low", "medium"), "medium") == "low"
    assert codex_forced_reasoning_effort(("medium", "high"), "medium") == "medium"
    assert DEFAULT_OPENAI_REASONING_EFFORT == "low"


# ── conversion: the developer role is NOT folded ───────────────────────────────────────
def test_developer_role_is_kept_not_folded():
    items = openai_input_items([{"role": "developer", "content": "permissions"}])
    assert items == [{"role": "developer", "content": "permissions"}]


def test_evidence_round_trip_is_function_call_and_output():
    messages = [
        {"role": "user", "content": "review this"},
        {
            "role": "assistant",
            "content": "let me check",
            "tool_calls": [{"id": "c1", "name": "exec_command", "arguments": '{"cmd":"ls"}'}],
        },
        {"role": "tool", "call_id": "c1", "output": "file.txt"},
    ]
    assert openai_input_items(messages) == [
        {"role": "user", "content": "review this"},
        {"role": "assistant", "content": "let me check"},
        {"type": "function_call", "name": "exec_command", "arguments": '{"cmd":"ls"}', "call_id": "c1"},
        {"type": "function_call_output", "call_id": "c1", "output": "file.txt"},
    ]


def test_openai_tools_passes_through_and_rejects_blanks():
    assert openai_tools([EXEC_COMMAND_TOOL])[0]["name"] == "exec_command"
    with pytest.raises(ConfigurationError):
        openai_tools([{"name": "x"}])  # missing type + parameters


# ── reply parsing ──────────────────────────────────────────────────────────────────────
def test_reply_reports_text_and_keeps_raw_argument_bytes():
    raw = '{"cmd":  "grep -r \\u0041 ."}'  # odd spacing + an escape, kept verbatim
    reply = reply_from_openai_response(
        Resp(function_call("c9", "exec_command", raw), output_text='{"outcome":"allow"}')
    )
    assert reply.text == '{"outcome":"allow"}'
    (call,) = reply.tool_calls
    assert call.id == "c9" and call.name == "exec_command"
    assert call.arguments == {"cmd": "grep -r A ."}
    assert call.raw_arguments == raw  # not re-encoded — the reviewer's own bytes survive
    assert call.arguments_error is None


def test_every_function_call_reported_including_unparseable():
    reply = reply_from_openai_response(
        Resp(
            function_call("c1", "exec_command", "not json"),
            function_call("c2", "exec_command", "[1,2]"),
            output_text="",
        )
    )
    assert reply.text is None  # empty text -> None -> engine files DERAILED
    assert len(reply.tool_calls) == 2
    assert reply.tool_calls[0].arguments_error.startswith(ARGUMENTS_PARSE_ERROR)
    assert reply.tool_calls[1].arguments_error == f"{ARGUMENTS_PARSE_ERROR}: expected an object"


def test_truncated_comes_from_status_not_text():
    done = reply_from_openai_response(Resp(output_text="{}", status="completed"))
    assert done.truncated is False
    cut = reply_from_openai_response(
        Resp(output_text="{", status="incomplete",
             incomplete_details=Details(reason="max_output_tokens"))
    )
    assert cut.truncated is True
    # an incomplete for any OTHER reason is NOT truncation (it is derailment/refusal)
    refused = reply_from_openai_response(
        Resp(output_text="", status="incomplete", incomplete_details=Details(reason="content_filter"))
    )
    assert refused.truncated is False


def test_usage_reads_reasoning_and_cached_tokens():
    reply = reply_from_openai_response(
        Resp(
            output_text="{}",
            usage=Details(
                input_tokens=100,
                output_tokens=40,
                output_tokens_details=Details(reasoning_tokens=30),
                input_tokens_details=Details(cached_tokens=64),
            ),
        )
    )
    assert reply.usage == Usage(
        input_tokens=100, output_tokens=40, reasoning_tokens=30, cache_read_tokens=64
    )


def test_missing_usage_is_zero_not_estimated():
    assert reply_from_openai_response(Resp(output_text="{}")).usage == Usage()


# ── the client: the request it puts on the wire ────────────────────────────────────────
def test_complete_sends_developer_system_schema_and_low_effort():
    transport = StubTransport(Resp(output_text='{"outcome":"allow"}'))
    client = OpenAIGuardianClient(model=MODEL, transport=transport)
    schema = {"type": "object", "properties": {"outcome": {"type": "string"}}}
    reply = client.complete(
        system="POLICY",
        messages=[{"role": "user", "content": "act"}],
        schema=schema,
        tools=[EXEC_COMMAND_TOOL],
        timeout=12.0,
    )
    assert isinstance(reply, GuardianReply) and reply.text == '{"outcome":"allow"}'
    (sent,) = transport.calls
    assert sent["model"] == MODEL
    assert sent["input"][0] == {"role": "developer", "content": "POLICY"}
    assert sent["input"][1] == {"role": "user", "content": "act"}
    assert sent["tools"][0]["name"] == "exec_command"
    assert sent["text"]["format"] == {
        "type": "json_schema",
        "name": OUTPUT_SCHEMA_NAME,
        "strict": OUTPUT_SCHEMA_STRICT,
        "schema": schema,
    }
    assert sent["reasoning"] == {"effort": "low"}
    assert sent["timeout"] == 12.0


def test_build_openai_client_is_api_key_auth_with_the_given_model():
    client = build_openai_client(model=MODEL)
    assert isinstance(client, OpenAIGuardianClient)
    assert client.model == MODEL
    assert client.chatgpt_auth is False  # API-key path, not ChatGPT OAuth
    assert client.reasoning_effort == "low"


def test_default_model_is_luna_and_empty_model_is_refused():
    assert OpenAIGuardianClient().model == DEFAULT_OPENAI_MODEL
    with pytest.raises(ConfigurationError):
        OpenAIGuardianClient(model="   ")
