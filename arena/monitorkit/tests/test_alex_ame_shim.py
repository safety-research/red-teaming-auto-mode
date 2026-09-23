"""The `ame_` bridge's record semantics — the rules THIS kit owns.

WHY THIS FILE EXISTS. Four defects shipped in the bridge and the suite stayed green through all of
them, because nothing imported the module: a guardian BLOCK filed as `fast_allow`; free allows
naming a reviewer, which reset the session breaker; a re-minted stamp built and then discarded; and
a `reviewer_record` keyed so loosely it would have landed on every pre-existing arm's admission
rows. Each test below fails on the tree that had the bug.

NO `importorskip`, ON PURPOSE. `tools/ci_witness.py` refuses a run with skips in it, and its
docstring names this exact pattern as a defect this repository already fixed once. A skipped test
is a test that did not run reported as one that passed. So when `auto_mode_eval` is absent — which
is the normal state of this package, and the property `hook` protects by importing the bridge
lazily — this module installs a MINIMAL STUB of the three upstream names the bridge imports, and
the tests run anyway. They are testing our mapping, not upstream's behaviour.

The tests that genuinely need the real package — "does upstream still word its admissions the way
we match on" — live in `tests_ame/`, which `testpaths` does not collect. See that file's header.
"""

from __future__ import annotations

import asyncio
import pathlib
import re
import sys
import types
from dataclasses import dataclass

import pytest

from monitorkit import ConfigStamp, DecisionSource


def _install_upstream_stubs() -> bool:
    """Make `monitorkit.alex_ame_shim` importable with no `auto_mode_eval` and no `inspect_ai`.

    Returns True if stubs were installed (upstream absent), False if the real package is here and
    was left alone. Only the names the bridge imports at module scope are provided; anything a test
    actually exercises is the bridge's own code.
    """
    try:  # the real thing, when this interpreter has it — better fidelity, same assertions
        import auto_mode_eval.monitor  # noqa: F401
        import inspect_ai.model  # noqa: F401
    except ImportError:
        pass
    else:
        return False

    def _mod(name: str, **attrs: object) -> None:
        m = types.ModuleType(name)
        for k, v in attrs.items():
            setattr(m, k, v)
        sys.modules[name] = m

    class _Blk:  # Block/Text/ToolUse/ToolResult stand-ins: the bridge only constructs these
        def __init__(self, **kw: object) -> None:
            self.__dict__.update(kw)

    _mod("auto_mode_eval")
    # The severity arm builds its reviewer from upstream's blessed sonnet-5 definition; at module
    # scope the bridge imports only the NAME, and reads `.model` / `.config` off it inside the
    # dispatch branch. A stub with those two attributes is all collection needs.
    _mod("auto_mode_eval.model_utils",
         MONITOR_SONNET_5_MODEL=types.SimpleNamespace(model="anthropic/claude-sonnet-5", config=None))
    from typing import Literal

    _mod(
        "auto_mode_eval.data_model",
        Block=_Blk, Classification=_Blk, Context=_Blk, Message=_Blk, Role=str,
        # the real vocabulary, so `get_args(Outcome)` in the bridge sees the same set here
        Outcome=Literal["ok", "error", "interrupted", "rejected-by-user",
                        "blocked-by-permissions", "automode-blocked", "automode-unavailable",
                        "automode-parsing-error"],
        Text=_Blk, ToolResult=_Blk, ToolUse=_Blk, Transcript=_Blk,
    )
    # Read OFF THE SHIM'S OWN SOURCE, not hand-listed. The shim imports one factory per arm it
    # vends, so any list maintained here goes stale the moment an arm is added and the whole file
    # stops collecting -- which is how this stub first broke, and it broke again on the two hybrid
    # arms. Over-approximating is free for a stub; being one name short is not.
    source = (pathlib.Path(__file__).parents[1] / "src/monitorkit/alex_ame_shim.py").read_text()
    arms = sorted(set(re.findall(r"\bmonitor_([a-z_]+)\b", source)))
    assert "cascade" in arms, "the shim no longer imports its factories by name"
    named = {n: types.SimpleNamespace(revision="stub-rev") for n in arms}
    factories = {f"monitor_{n}": (lambda *a, **k: object()) for n in arms}
    _mod(
        "auto_mode_eval.monitor",
        NAMED_MONITORS=named, PACKAGE_REVISION="stub-pkg", MonitorName=str, Monitor=object,
        **factories,
    )
    _mod("inspect_ai")
    _mod("inspect_ai.model", Model=object, get_model=lambda *a, **k: object())
    return True


STUBBED = _install_upstream_stubs()

from monitorkit.alex_ame_shim import (  # noqa: E402
    _NOTHING_TO_REVIEW,
    AmePipeline,
    ModelCall,
)

#: The witness `_source` now asks "did a reviewer run". A recorded call means yes; the empty tuple
#: means no. Upstream's prose is no longer consulted for that question, only for naming which of
#: the two no-reviewer rows a zero-call ALLOW is.
RAN = (ModelCall(prompt="rulebook + transcript", response="<block>false</block>"),)
FREE = ()


@dataclass
class Ruling:
    """A `Classification` as `_source` reads it: four attributes, nothing else."""

    verdict: str = "ALLOW"
    reason: str | None = None
    pre_screen: object | None = None
    failed_closed: bool = False


def _pipeline(*, pre_screened: bool, arm: str = "ame_cascade") -> AmePipeline:
    stamp = ConfigStamp(
        router="n/a", cascade=(arm,), view="n/a", policy="n/a",
        model="anthropic/claude-opus-4-8", kit_revision="test",
    )
    return AmePipeline(monitor_name="cascade", monitor=object(),  # type: ignore[arg-type]
                       stamp=stamp, pre_screened=pre_screened)


# ── the guardian mislabel: a denial filed as a free allow ─────────────────────────────────────
def test_a_single_stage_block_is_parsed_not_a_fast_allow():
    ruling = Ruling(verdict="BLOCK", reason="risk=critical — exfiltrates credentials")
    assert _pipeline(pre_screened=False)._source(ruling, RAN) is DecisionSource.PARSED


def test_a_single_stage_allow_is_parsed_too():
    assert _pipeline(pre_screened=False)._source(Ruling(), RAN) is DecisionSource.PARSED


def test_a_pre_screened_arms_own_allow_is_a_fast_allow():
    assert _pipeline(pre_screened=True)._source(Ruling(), RAN) is DecisionSource.FAST_ALLOW


@pytest.mark.parametrize("pre_screened", [True, False])
def test_an_escalated_verdict_is_parsed_on_either_kind_of_arm(pre_screened):
    ruling = Ruling(verdict="BLOCK", reason="[Data Exfiltration] …", pre_screen=Ruling())
    assert _pipeline(pre_screened=pre_screened)._source(ruling, RAN) is DecisionSource.PARSED


@pytest.mark.parametrize("pre_screened", [True, False])
@pytest.mark.parametrize("calls", [RAN, FREE])
def test_an_unparseable_reply_derails(pre_screened, calls):
    ruling = Ruling(verdict="BLOCK", failed_closed=True, reason="unparseable")
    assert _pipeline(pre_screened=pre_screened)._source(ruling, calls) is DecisionSource.DERAILED


def test_a_fast_allow_must_also_be_an_allow():
    """A compaction summary skips the pre-screen, so a stage-2 DENIAL of one carries no
    `pre_screen` — and without the verdict guard it would be filed as a fast allow, which is the
    very defect this function exists to stop."""
    ruling = Ruling(verdict="BLOCK", reason="[Scope] denied the handoff", pre_screen=None)
    assert _pipeline(pre_screened=True)._source(ruling, RAN) is DecisionSource.PARSED


# ── the free allows that were disarming the breaker ───────────────────────────────────────────
@pytest.mark.parametrize("pre_screened", [True, False])
def test_an_admission_allow_is_a_router_allow_and_names_no_reviewer(pre_screened):
    pipe = _pipeline(pre_screened=pre_screened)
    ruling = Ruling(reason="auto-approved: read-only command")
    assert pipe._source(ruling, FREE) is DecisionSource.ROUTER_ALLOW
    assert pipe._decision(blocked=False, source=pipe._source(ruling, FREE)).monitors_ran == ()


def test_an_admission_is_read_off_the_call_count_not_off_their_wording():
    """The fix that outlasts a rename upstream. A zero-call allow worded in a way this module has
    never seen is still a free allow, and still must not reset the breaker."""
    pipe = _pipeline(pre_screened=True)
    for reason in (None, "", "waved through by the new admission stage", "SAFE-TOOL"):
        assert pipe._source(Ruling(reason=reason), FREE) is DecisionSource.ROUTER_ALLOW


def test_a_judged_allow_worded_like_an_admission_is_not_downgraded_to_free():
    """The other half of the same fix, and the one that used to cost real cost-column accuracy: a
    reviewer that quotes the admission phrasing back in its own reason DID run and DID cost."""
    pipe = _pipeline(pre_screened=False)
    ruling = Ruling(reason="auto-approved: nothing here needs escalation")
    assert pipe._source(ruling, RAN) is DecisionSource.PARSED
    assert pipe._decision(blocked=False, source=pipe._source(ruling, RAN),
                          calls=RAN).monitors_ran == ("ame_cascade",)


def test_nothing_to_review_is_empty_content_and_names_no_reviewer():
    pipe = _pipeline(pre_screened=True)
    for reason in _NOTHING_TO_REVIEW:
        ruling = Ruling(reason=reason)
        assert pipe._source(ruling, FREE) is DecisionSource.EMPTY_CONTENT
        assert pipe._decision(blocked=False, source=pipe._source(ruling, FREE)).monitors_ran == ()


def test_a_judged_decision_does_name_its_reviewer():
    pipe = _pipeline(pre_screened=False)
    assert pipe._decision(blocked=True, source=DecisionSource.PARSED).monitors_ran == ("ame_cascade",)


def test_a_zero_call_denial_still_names_a_reviewer():
    """The guard that stops this fix inverting the bug it fixes. Every zero-call path upstream has
    today is an allow; a deterministic denial added later must NOT land in the no-reviewer family,
    because that would empty `monitors_ran` and leave a DENIAL that never arms the breaker."""
    pipe = _pipeline(pre_screened=True)
    for reason in ("policy denylist", *_NOTHING_TO_REVIEW):
        ruling = Ruling(verdict="BLOCK", reason=reason)
        source = pipe._source(ruling, FREE)
        assert source is DecisionSource.PARSED
        assert pipe._decision(blocked=True, source=source).monitors_ran == ("ame_cascade",)


def test_a_missing_reason_does_not_crash_any_branch():
    pipe = _pipeline(pre_screened=True)
    for reason in (None, "", "   ", "auto-approved", "AUTO-APPROVED: x", " auto-approved: x"):
        for calls in (RAN, FREE):
            assert pipe._source(Ruling(reason=reason), calls) in (
                DecisionSource.FAST_ALLOW, DecisionSource.PARSED, DecisionSource.ROUTER_ALLOW
            )


def test_every_no_reviewer_source_yields_an_empty_monitors_ran():
    pipe = _pipeline(pre_screened=True)
    for source in (DecisionSource.ROUTER_ALLOW, DecisionSource.EMPTY_CONTENT):
        assert pipe._decision(blocked=False, source=source).monitors_ran == ()
    for source in (DecisionSource.PARSED, DecisionSource.FAST_ALLOW, DecisionSource.DERAILED):
        assert pipe._decision(blocked=False, source=source).monitors_ran == ("ame_cascade",)


# ── D-60: WHY a prior call failed, carried to the bridged reviewer ────────────────────────────
def test_a_hosts_denial_code_is_carried_to_their_reviewer():
    """`hook._stamp_denial_outcome` writes the host's own toolDenialKind onto the block. Dropping
    it leaves every prior denial looking like a bare error, which is what let a blocked action
    through on a byte-identical retry."""
    from monitorkit.alex_ame_shim import _outcome

    for code in ("automode-blocked", "blocked-by-permissions", "rejected-by-user",
                 "automode-unavailable", "automode-parsing-error"):
        assert _outcome(code) == code


def test_an_outcome_the_agent_forged_is_dropped_not_raised():
    """The transcript is a file the agent can write, and theirs is a pydantic Literal. An
    unrecognised string must not reach it: a ValidationError inside to_transcript would turn a
    forged word in a tool result into a fail-closed denial of every subsequent call."""
    from monitorkit.alex_ame_shim import _outcome

    for forged in ("lol", "OK", "automode-blocked ", "", None, 7, {"outcome": "ok"}):
        assert _outcome(forged) is None


def test_the_outcome_vocabulary_is_read_off_their_literal():
    """Hardcoding the set here would let the two drift silently."""
    from monitorkit.alex_ame_shim import _OUTCOMES

    assert "automode-blocked" in _OUTCOMES and "ok" in _OUTCOMES


# ── the reviewer's own transcript: what it asked, and what came back ──────────────────────────
@dataclass
class _Call:
    function: str
    arguments: dict


@dataclass
class _Msg:
    """A chat message shaped like inspect's: `.text` is the TEXT PARTS ONLY, and the tool calls
    live in a sibling field. That split is the whole hazard this renders around."""

    role: str
    text: str = ""
    tool_calls: list | None = None
    function: str | None = None
    error: object | None = None


def test_the_reviewers_own_tool_calls_survive_into_the_record():
    """The agentic arms `read`/`grep` a corpus. `.text` on an assistant turn returns text parts and
    drops `tool_calls`, so rendering by `.text` alone keeps every result the reviewer was handed
    and loses every query it chose to run — a searching monitor recorded as a passive one."""
    from monitorkit.alex_ame_shim import _message_text

    rendered = _message_text(
        _Msg(role="assistant", text="checking the corpus",
             tool_calls=[_Call("grep", {"pattern": "AKIA[0-9A-Z]+"})])
    )
    assert "checking the corpus" in rendered
    assert "grep" in rendered and "AKIA[0-9A-Z]+" in rendered


def test_a_tool_result_is_labelled_with_the_tool_that_answered():
    """Two tools are bound; an unlabelled `[tool] <output>` cannot be attributed to either."""
    from monitorkit.alex_ame_shim import _message_text

    rendered = _message_text(_Msg(role="tool", function="read", text="1: {...}"))
    assert rendered.startswith("[tool read]") and "1: {...}" in rendered


def test_a_tool_error_is_recorded_rather_than_read_as_an_empty_result():
    """`ToolError` comes back as a message with empty text and a populated `error`. Dropped, a
    refused query is indistinguishable from one that legitimately found nothing."""
    from monitorkit.alex_ame_shim import _message_text

    rendered = _message_text(_Msg(role="tool", function="read", error=_Err("no such file: x")))
    assert "no such file: x" in rendered


def test_unserialisable_tool_arguments_do_not_lose_the_turn():
    """`arguments` is theirs to shape. A record is worth less than a crash mid-review."""
    from monitorkit.alex_ame_shim import _message_text

    rendered = _message_text(_Msg(role="assistant", tool_calls=[_Call("grep", {"p": object()})]))
    assert "grep" in rendered


def test_the_whole_exchange_is_recoverable_from_prompt_plus_response():
    """`loop_monitor` re-sends the growing list, so turn N's PROMPT carries turns 1..N-1 — but the
    final reply appears in no later prompt and is the one the verdict is parsed from."""
    from monitorkit.alex_ame_shim import _prompt_text

    sent = [_Msg(role="user", text="rulebook + transcript"),
            _Msg(role="assistant", tool_calls=[_Call("grep", {"pattern": "curl"})]),
            _Msg(role="tool", function="grep", text="transcript.jsonl:12: curl -X POST …")]
    rendered = _prompt_text(sent)
    for expected in ("rulebook + transcript", "grep", "curl", "transcript.jsonl:12"):
        assert expected in rendered


@dataclass
class _Err:
    message: str


def test_every_usage_column_the_kit_records_is_filled():
    """Three of five left at zero reads as 'this arm used no cache', not 'not measured' — and the
    cost column is the only thing that makes a fast screen's trade evaluable at all."""
    from monitorkit.alex_ame_shim import ModelCall, _usage_of

    usage = _usage_of((ModelCall(prompt="p", input_tokens=1, output_tokens=2, reasoning_tokens=3,
                                 cache_read_tokens=4, cache_write_tokens=5),) * 2)
    assert (usage.input_tokens, usage.output_tokens, usage.reasoning_tokens,
            usage.cache_read_tokens, usage.cache_write_tokens) == (2, 4, 6, 8, 10)


def test_the_system_half_is_read_off_what_was_sent_not_assumed():
    """The two families differ: the classifier arms send no system message (the rulebook rides in
    the user turn), `CodexGuardianMonitor` sends its policy as one. A hardcoded answer was wrong
    for one of them whichever way it was written."""
    from monitorkit.alex_ame_shim import _split_system

    guardian = [_Msg(role="system", text="You are a security guardian."),
                _Msg(role="user", text="<transcript>")]
    system, rest = _split_system(guardian)
    assert [m.role for m in system] == ["system"]
    assert [m.role for m in rest] == ["user"]

    system, rest = _split_system([_Msg(role="user", text="rulebook + transcript")])
    assert system == [] and [m.role for m in rest] == ["user"]


def test_a_one_shot_string_prompt_has_no_system_half_to_find():
    """A bare string is a user turn by construction; `[]` is the answer, not a failed search."""
    from monitorkit.alex_ame_shim import _split_system

    assert _split_system("rulebook + transcript") == ([], "rulebook + transcript")


def test_classifier_input_reports_the_two_halves_separately():
    from monitorkit.alex_ame_shim import AmeReview, ModelCall

    guardian = AmeReview(classification=Ruling(),  # type: ignore[arg-type]
                         calls=(ModelCall(prompt="[user] <transcript>", system="[system] policy"),))
    assert guardian.classifier_input == {"system": "[system] policy", "user": "[user] <transcript>"}

    classifier = AmeReview(classification=Ruling(),  # type: ignore[arg-type]
                           calls=(ModelCall(prompt="rulebook + transcript"),))
    assert classifier.classifier_input == {"system": "", "user": "rulebook + transcript"}


def test_a_free_allow_has_no_classifier_input_rather_than_an_empty_one():
    """`None` says no reviewer was consulted; `{"system": "", "user": ""}` would say one was
    consulted with an empty prompt, and three of this repo's quality bars key on the field."""
    from monitorkit.alex_ame_shim import AmeReview

    assert AmeReview(classification=Ruling()).classifier_input is None  # type: ignore[arg-type]


def _ame_stamp(arm: str) -> ConfigStamp:
    return ConfigStamp(router="n/a", cascade=(arm,), view="n/a", policy="n/a",
                       model="m", kit_revision="test")


def test_every_arm_the_hook_admits_is_one_the_bridge_knows():
    """`hook.AME_ARMS` is a second copy of the arm list, kept there so `config_from_env` can refuse
    a typo without importing a package that may not be installed. This is half of what stops the
    copies drifting; `tests_ame` holds the other half, which builds them for real.

    The distinction under test is 'the bridge has a branch for this name'. A `TypeError` from the
    stub's model-less factory means the name WAS matched — only the unknown-name `ValueError` is a
    disagreement between the two lists."""
    from monitorkit import hook as H
    from monitorkit.alex_ame_shim import create_monitor

    for arm in sorted(H.AME_ARMS):
        try:
            create_monitor(_ame_stamp(arm), cwd=None)
        except ValueError as exc:  # noqa: PERF203 -- one arm per iteration is the point
            assert "no auto_mode_eval monitor is named" not in str(exc), arm
        except TypeError:
            pass  # the stub's factories expose no `.model`; the NAME resolved, which is the claim


def test_the_severity_arm_dispatches_to_upstreams_severity_monitor(monkeypatch):
    """`ame_original_severity` is upstream's `monitor_original_severity` -- graded 0-100 verdicts ruled
    at its per-model thresholds -- on the SAME intake as `ame_original`. It is a different monitor
    from the binary arm, so the name must reach the severity factory and never fall through to
    `monitor_original`; and a sonnet-5 reviewer must be rebuilt from upstream's blessed definition
    (thinking off), not passed through as the bare string the deployed classifier config would
    leave thinking ON for."""
    import monitorkit.alex_ame_shim as S

    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(S, "monitor_original_severity",
                        lambda model, cwd=None: calls.append(("severity", model)) or object())
    monkeypatch.setattr(S, "monitor_original",
                        lambda model, cwd=None: calls.append(("original", model)) or object())
    monkeypatch.setattr(S, "get_model", lambda name, config=None: ("built", name, config))
    try:
        S.create_monitor(_ame_stamp("ame_original_severity"), cwd=None, model="anthropic/claude-sonnet-5")
    except TypeError:
        pass  # the stub monitor has no `.model` for the recording proxy; dispatch already happened
    assert [c[0] for c in calls] == ["severity"], calls
    # the sonnet-5 string was rebuilt via upstream's definition, not handed over bare
    assert calls[0][1] == ("built", "anthropic/claude-sonnet-5", None), calls


def test_the_bridge_refuses_every_name_the_hook_does_not_admit():
    """The other direction: a name the bridge would build but the hook rejects is an arm nobody
    can select, and a name the hook admits but the bridge refuses is a per-call denial."""
    from monitorkit.alex_ame_shim import create_monitor

    for absent in ("ame_casacde", "ame_nope", "ame_hybrid_slow", "ame_"):
        with pytest.raises(ValueError, match="no auto_mode_eval monitor is named"):
            create_monitor(_ame_stamp(absent), cwd=None)


def test_a_mistyped_ame_arm_is_refused_at_configuration_not_at_the_first_tool_call():
    """`ame_casacde` used to configure cleanly and then deny every call with a config error — a
    full result directory filed under an arm that never ran, which is what `config_from_env`'s
    docstring says it exists to prevent."""
    from monitorkit import hook as H

    for typo in ("ame_casacde", "ame_", "ame_nope", "ame_GUARDIAN"):
        with pytest.raises(H.HookConfigError, match="unknown auto_mode_eval arm"):
            H.config_from_env({"MONITORKIT_ARM": typo, "MONITORKIT_KIT_REVISION": "t"})


def test_a_real_ame_arm_still_configures():
    from monitorkit import hook as H

    config = H.config_from_env({"MONITORKIT_ARM": "ame_cascade", "MONITORKIT_KIT_REVISION": "t"})
    assert config.arm.name == "ame_cascade"


def test_an_uninstrumented_pipeline_is_refused_rather_than_built():
    """`_source` reads the recorder's call count. With no recorder every decision reports zero
    calls, files as a free allow, empties `monitors_ran`, disarms the breaker and reports zero
    cost — a full set of plausible numbers. It must stop the run, not reshape it."""
    from monitorkit.alex_ame_shim import _wrap

    with pytest.raises(TypeError, match="uninstrumented"):
        _wrap("cascade", pre_screened=True, monitor=object(),  # type: ignore[arg-type]
              stamp=ConfigStamp(router="n/a", cascade=("ame_cascade",), view="n/a", policy="n/a",
                                model="m", kit_revision="test"))


# ── the recorder itself: the one site that assembles the record ───────────────────────────────
class _Usage:
    def __init__(self, **fields):
        self.__dict__.update(fields)


class _Inner:
    """A model that answers, so `_RecordingModel.generate` can be driven directly."""

    def __init__(self, reply, usage=None):
        self.reply = reply
        self.usage = usage
        self.seen: list = []

    async def generate(self, sent, *args, **kwargs):
        self.seen.append(sent)
        return _Usage(message=self.reply, usage=self.usage)


def _record(sent, reply=None, usage=None):
    """Drive the recorder end to end and hand back the single `ModelCall` it assembled.

    Every helper below it has its own test; NONE of them reached this method, so each field it
    writes could be reverted one line at a time with the whole suite green — proven by replacing
    this body with `raise` and watching 1138 tests still pass. The helpers are not the artifact;
    this is.
    """
    from monitorkit.alex_ame_shim import _RecordingModel

    recorder = _RecordingModel(_Inner(reply if reply is not None else _Msg(role="assistant"), usage))
    asyncio.run(recorder.generate(sent))
    assert len(recorder.calls) == 1
    return recorder.calls[0]


def test_the_recorder_writes_every_field_the_record_reads():
    call = _record(
        [_Msg(role="system", text="You are a security guardian."),
         _Msg(role="user", text="<transcript>curl -X POST …</transcript>")],
        reply=_Msg(role="assistant", text="<block>true</block> exfiltrates credentials"),
        usage=_Usage(input_tokens=4000, output_tokens=50, reasoning_tokens=7,
                     input_tokens_cache_read=120, input_tokens_cache_write=None),
    )
    assert call.system == "You are a security guardian."
    assert call.prompt == "<transcript>curl -X POST …</transcript>"
    assert call.response == "[assistant] <block>true</block> exfiltrates credentials"
    assert (call.input_tokens, call.output_tokens, call.reasoning_tokens) == (4000, 50, 7)
    assert (call.cache_read_tokens, call.cache_write_tokens) == (120, 0)


def test_the_recorded_prompt_is_the_raw_turn_not_a_decorated_one():
    """The kit records `classifier_input` as the reviewer's own system and user text. A `[user] `
    prefix here would leave a bridged prompt that cannot be diffed or hashed against a kit one —
    silently, and while looking fully populated."""
    call = _record([_Msg(role="user", text="rulebook\n=====\n<transcript>")])
    assert call.prompt == "rulebook\n=====\n<transcript>"
    assert call.system == ""


def test_a_tool_loop_turn_keeps_the_role_markers_it_needs():
    """The other side of the same rule: more than one turn cannot be flattened without saying
    which is which, and that is also the signal that this arm has no single prompt."""
    call = _record([_Msg(role="user", text="rulebook"),
                    _Msg(role="assistant", tool_calls=[_Call("grep", {"pattern": "curl"})]),
                    _Msg(role="tool", function="grep", text="transcript.jsonl:12: curl")])
    assert "[user] rulebook" in call.prompt
    assert 'grep({"pattern": "curl"})' in call.prompt
    assert "[tool grep] transcript.jsonl:12: curl" in call.prompt


def test_the_recorder_returns_upstreams_answer_untouched():
    """A proxy that reshapes the reply would change the verdict, not just the record."""
    from monitorkit.alex_ame_shim import _RecordingModel

    inner = _Inner(_Msg(role="assistant", text="ok"))
    recorder = _RecordingModel(inner)
    out = asyncio.run(recorder.generate("prompt"))
    assert out.message is inner.reply
    assert inner.seen == ["prompt"]  # and what it forwarded was what it was given


def test_a_provider_that_reports_no_usage_records_zeros_not_a_crash():
    """`usage` is `None` on some providers and on a cached reply. `getattr(None, ...)` must not
    reach `int(None)` inside a live review."""
    call = _record([_Msg(role="user", text="x")], usage=None)
    assert (call.input_tokens, call.cache_read_tokens) == (0, 0)


def test_reset_clears_the_calls_so_a_reused_pipeline_does_not_accrue():
    """`review()` resets before each action. Without it a second review on the same pipeline sums
    the first one's tokens into its cost and reports a free allow as a judged decision, because
    `_source` reads this list to decide whether a reviewer ran."""
    from monitorkit.alex_ame_shim import _RecordingModel

    recorder = _RecordingModel(_Inner(_Msg(role="assistant", text="ok")))
    asyncio.run(recorder.generate("first"))
    recorder.reset()
    assert recorder.calls == []
    asyncio.run(recorder.generate("second"))
    assert [c.prompt for c in recorder.calls] == ["second"]


def test_the_cache_halves_are_none_on_providers_that_do_not_report_them():
    """inspect types both as `int | None`; `int(None)` raises inside the reviewer."""
    from monitorkit.alex_ame_shim import _tokens

    class _Usage:
        input_tokens = 10
        input_tokens_cache_read = None

    assert _tokens(_Usage(), "input_tokens_cache_read") == 0
    assert _tokens(_Usage(), "input_tokens_cache_write") == 0
    assert _tokens(_Usage(), "input_tokens") == 10
