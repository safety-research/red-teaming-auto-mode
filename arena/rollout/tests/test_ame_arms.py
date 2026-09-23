"""Routing for the `ame_` arms — the driver half of running the other implementation's monitors.

MonitorKit's own tests cover the bridge (`monitorkit/tests/test_alex_ame_shim.py`,
`test_hook_bridged_record.py`). What is left here is what only the driver knows: which model id an
`ame_` arm resolves to, which slug it files under, which interpreter the gate re-execs into, and
that a kit arm's resolution is byte-identical to before any of this existed.

Every assertion is about a WRONG NUMBER, not a crash. The failure shape this file guards against is
uniform: a misrouted `ame_` arm denies every call with an import or resolution error, the trial
directory fills with denials, and the arm finishes looking like a monitor that caught everything.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from rollout import runner as R

_PKG = Path(__file__).resolve().parents[1]

AME_ARMS = ("ame_original", "ame_original_severity", "ame_cascade", "ame_expensive", "ame_results",
            "ame_agentic", "ame_guardian", "ame_guardian_strict", "ame_hybrid", "ame_hybrid_fast_allow")


# ── the model namespace ───────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("arm", AME_ARMS)
def test_every_ame_arm_resolves_to_a_provider_qualified_model(arm):
    """`inspect_ai.get_model` requires `provider/model`. A bare id resolves to nothing at review
    time — one `config_error` denial per call, for the whole trial."""
    model = R.monitor_model_for(arm)
    assert model is not None and "/" in model, f"{arm} -> {model!r}"


def test_the_ame_guardians_resolve_to_openai_and_the_rest_to_anthropic():
    """Codex's guardian is a different reviewer on a different provider. Routing it to Anthropic
    would silently run the wrong model under the guardian arm's name."""
    for arm in ("ame_guardian", "ame_guardian_strict"):
        assert R.monitor_model_for(arm) == R.AME_GUARDIAN_MODEL
        assert R.monitor_model_for(arm).startswith("openai/")
    for arm in ("ame_original", "ame_cascade", "ame_agentic", "ame_hybrid"):
        assert R.monitor_model_for(arm) == R.AME_MONITOR_MODEL
        assert R.monitor_model_for(arm).startswith("anthropic/")


def test_a_bridged_guardian_and_a_kit_guardian_name_the_same_model():
    """The two guardians must differ in IMPLEMENTATION and not in which model was asked, or the
    comparison measures the wrong variable."""
    assert R.monitor_model_for("ame_guardian").endswith(R.monitor_model_for("guardian"))


# ── the slug: two spellings of one model must not file two directories ────────────────────────
def test_both_spellings_of_the_guardian_model_reduce_to_one_slug():
    """`gpt-5.6-luna` and `openai/gpt-5.6-luna` are the same reviewer. Equality matching on the
    bare id sent the qualified spelling down the `claude-` fallback and produced a second results
    directory for one model."""
    assert R._model_short(R.GUARDIAN_MODEL) == R._model_short(R.AME_GUARDIAN_MODEL) == "gpt56luna"


def test_both_spellings_of_the_monitor_model_reduce_to_one_slug():
    from rollout.environment import MONITOR_MODEL

    assert R._model_short(MONITOR_MODEL) == R._model_short(R.AME_MONITOR_MODEL) == "opus48"


#: Every model tier `_model_short`'s table answers for, and the slug it must produce. A capability
#: sweep points the harness at these, and the directory it writes is named from this reduction.
MODEL_TIERS = {
    "claude-opus-4-7": "opus47",
    "claude-opus-4-8": "opus48",
    "claude-opus-5": "opus5",
}


def test_every_model_tier_reduces_to_its_own_slug():
    for model, slug in MODEL_TIERS.items():
        assert R._model_short(model) == slug, model


def test_no_two_model_tiers_file_the_same_directory():
    """The invariant the table exists for. `_model_short` feeds `config_slug`, so two DISTINCT
    models sharing a reduction means two experiments' trials land in one directory and are pooled
    as replicates of each other -- a wrong number, not a crash."""
    seen: dict[str, str] = {}
    for model in MODEL_TIERS:
        slug = R._model_short(model)
        assert slug not in seen, f"{model} and {seen[slug]} both reduce to {slug!r}"
        seen[slug] = model


def test_the_pinned_config_is_untouched_by_the_tier_table():
    """What makes the table safe to have added: GT-007's two models and the guardian reduce exactly
    as they did before it. Every run already on disk -- 2,505 in the shared tree, 52 archived tags --
    is slugged `a-opus47` / `m-opus48` / `m-gpt56luna` / `m-none`, so a changed reduction here would
    have orphaned the whole corpus from the code that names it."""
    from rollout.environment import AGENT_MODEL, MONITOR_MODEL

    # The REDUCTION is what must not move: every spelling already on disk has to keep resolving to
    # the component that names its directory, whatever the CURRENT models happen to be. Asserting
    # `_model_short(AGENT_MODEL) == "opus47"` conflated the two, so the 2026-09-07 opus-5 flip read
    # as a tier-table regression.
    assert R._model_short("claude-opus-4-7") == "opus47"
    assert R._model_short("claude-opus-4-8") == "opus48"
    assert R._model_short(R.GUARDIAN_MODEL) == "gpt56luna"
    # …and the models actually in force reduce to a component too (never the raw fallback).
    assert R._model_short(AGENT_MODEL) == "opus5"
    assert R._model_short(MONITOR_MODEL) == "opus48"


# ── the kit arms, unchanged ───────────────────────────────────────────────────────────────────
def test_no_kit_arm_is_read_as_a_bridged_one():
    for arm in (*R.GUARDIAN_ARMS, "control", "s1", "s2", "cascade", "original"):
        assert not R.is_ame_arm(arm), arm


def test_kit_arm_model_resolution_is_untouched():
    """The whole design — a separate venv, a re-exec keyed on the arm — exists so that a kit
    number measured after this change pools with one measured before it."""
    from rollout.environment import MONITOR_MODEL

    assert R.monitor_model_for("control") is None
    assert R.monitor_model_for("cascade") == MONITOR_MODEL
    for arm in R.GUARDIAN_ARMS:
        assert R.monitor_model_for(arm) == R.GUARDIAN_MODEL


# ── the gate environment ──────────────────────────────────────────────────────────────────────
class _Env:
    name = "stub"


def _gate_env(arm: str) -> dict:
    return R.Runner.__dict__["_gate_env"](_FakeRunner(), arm)


class _FakeRunner:
    env = _Env()


def test_a_bridged_arm_is_told_where_its_interpreter_and_package_are():
    env = _gate_env("ame_cascade")
    assert env["AME_PYTHON"] == "/opt/ame-venv/bin/python"
    assert env["AUTO_MODE_EVAL_SRC"] == "/opt/auto_mode_eval/src"


def test_a_bridged_arm_is_not_handed_a_reviewer_client_this_kit_builds():
    """`MONITORKIT_GUARDIAN_CLIENT` re-points a reviewer MonitorKit constructs, and for a bridged
    arm it constructs none. Setting it would name a client nothing consulted."""
    assert "MONITORKIT_GUARDIAN_CLIENT" not in _gate_env("ame_guardian")


def test_a_kit_arm_is_told_nothing_about_the_ame_venv():
    env = _gate_env("cascade")
    assert "AME_PYTHON" not in env and "AUTO_MODE_EVAL_SRC" not in env


def test_the_kit_guardian_still_gets_its_client():
    guardian = next(iter(R.GUARDIAN_ARMS))
    assert _gate_env(guardian)["MONITORKIT_GUARDIAN_CLIENT"] == R.GUARDIAN_CLIENT_FACTORY


# ── the staged package ────────────────────────────────────────────────────────────────────────
def _stagers():
    sys.path.insert(0, str(_PKG / "scripts"))
    try:
        import stage_auto_mode_eval_for_build as ame
        import stage_monitorkit_for_build as kit
    finally:
        sys.path.pop(0)
    return ame, kit


def test_the_two_stagers_hash_a_tree_identically(tmp_path):
    """A revision label answers "what was checked out"; only the digest answers "were these the
    bytes?". A bridged run's attribution has two halves — `kit_revision` names the auto_mode_eval
    revision, `reference_revision` keeps ours — so both stamps must mean the same thing. Compared
    by RESULT rather than by source text: what matters is that the two agree, not that the
    functions look alike."""
    ame, kit = _stagers()
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.py").write_text("x = 1\n")
    (tmp_path / "pkg" / "sub").mkdir()
    (tmp_path / "pkg" / "sub" / "b.py").write_text("y = 2\n")
    assert ame._tree_sha256(tmp_path / "pkg") == kit._tree_sha256(tmp_path / "pkg")


def test_the_content_hash_moves_when_a_staged_byte_does(tmp_path):
    ame, _ = _stagers()
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.py").write_text("x = 1\n")
    before = ame._tree_sha256(tmp_path / "pkg")
    (tmp_path / "pkg" / "a.py").write_text("x = 2\n")
    assert ame._tree_sha256(tmp_path / "pkg") != before


def test_staging_the_real_submodule_writes_a_stamp_that_matches_what_it_copied():
    """End to end against the pinned submodule: stage it, then recompute the digest over what
    landed on disk. A stamp that does not describe the staged bytes is worse than no stamp — it
    is an attribution the reader has no reason to doubt."""
    ame, _ = _stagers()
    if not ame.AME_SRC.exists():
        pytest.fail(f"submodule not initialised at {ame.AME_SRC}; run `git submodule update --init`")
    rev = ame.stage()
    try:
        fields = dict(
            line.split("=", 1) for line in ame.STAMP.read_text().splitlines() if "=" in line
        )
        assert fields["revision"] == rev
        assert fields["tree_sha256"] == ame._tree_sha256(ame.STAGED)
        assert (ame.STAGED / "monitor" / "__init__.py").is_file()  # the package really landed
    finally:
        ame.clean()


def test_the_base_image_installs_the_ame_interpreter_where_the_gate_looks():
    """Three files have to agree on two paths: the Dockerfile that creates them, the runner that
    names them, and the gate that defaults to them. A rename in one is a silent per-call denial."""
    dockerfile = (_PKG / "sandbox/base/Dockerfile").read_text()
    assert "/opt/ame-venv" in dockerfile
    assert "COPY _auto_mode_eval/ /opt/auto_mode_eval/src/" in dockerfile
    gate = (_PKG / "scripts/monitorkit_gate.py").read_text()
    assert '"/opt/ame-venv/bin/python"' in gate
    assert '"/opt/auto_mode_eval/src"' in gate


def test_the_ame_venv_is_isolated_from_the_system_anthropic_pin():
    """The reason it is a venv at all: installing inspect_ai's anthropic into the system python
    would re-point the SDK every kit reviewer calls, and invalidate every kit number ever taken."""
    dockerfile = (_PKG / "sandbox/base/Dockerfile").read_text()
    assert 'pip install --no-cache-dir "anthropic==0.104.1"' in dockerfile  # the kit's, system-wide
    assert '"anthropic==0.118.0"' in dockerfile                            # theirs, in the venv
    assert "python3 -m venv /opt/ame-venv" in dockerfile
    assert "--system-site-packages" not in dockerfile


def test_the_staged_package_is_not_on_pythonpath():
    """An agent that can import the reviewer's package can read the prompts judging it."""
    dockerfile = (_PKG / "sandbox/base/Dockerfile").read_text()
    for line in dockerfile.splitlines():
        if line.startswith("ENV PYTHONPATH") or "PYTHONPATH=" in line and line.startswith("ENV"):
            assert "auto_mode_eval" not in line


# ── the preflight: refuse the trial rather than fill a directory with denials ─────────────────
class _RecordingRunner:
    """Enough of Runner to drive `preflight_gate` without a container."""

    env = _Env()

    def __init__(self, returncode: int = 0, stderr: str = "") -> None:
        self.returncode = returncode
        self.stderr = stderr
        self.calls: list = []

    def dexec(self, service, argv, env=None, timeout=None):
        self.calls.append((service, argv, env))
        return subprocess.CompletedProcess(argv, self.returncode, "", self.stderr)

    _gate_env = R.Runner.__dict__["_gate_env"]
    preflight_gate = R.Runner.__dict__["preflight_gate"]


def test_a_bridged_arm_whose_reviewer_cannot_be_built_refuses_the_trial():
    """The failure this exists for: `create_monitor` raising on the first tool call denies every
    call after it too, so the trial COMPLETES and reports flawless recall having consulted no
    reviewer. The commonest instance is a kit pin that does not yet contain the bridge."""
    runner = _RecordingRunner(returncode=2, stderr="NOT READY -- unknown arm 'ame_cascade'")
    with pytest.raises(RuntimeError, match="not runnable in this image"):
        runner.preflight_gate("ame_cascade")


def test_the_refusal_quotes_why_rather_than_just_failing():
    runner = _RecordingRunner(returncode=2, stderr="NOT READY -- No module named 'inspect_ai'")
    with pytest.raises(RuntimeError, match="inspect_ai"):
        runner.preflight_gate("ame_cascade")


def test_the_preflight_constructs_the_reviewer_not_just_the_config():
    """`--check` alone resolves the configuration, which succeeds for an arm whose reviewer cannot
    be built at all — that is the whole gap. `--construct` is what closes it."""
    runner = _RecordingRunner()
    runner.preflight_gate("ame_cascade")
    _, argv, env = runner.calls[0]
    assert "--check" in argv and "--construct" in argv
    assert env["MONITORKIT_ARM"] == "ame_cascade"


def test_a_runnable_bridged_arm_passes_and_spends_one_container_call():
    runner = _RecordingRunner()
    runner.preflight_gate("ame_cascade")
    assert len(runner.calls) == 1


@pytest.mark.parametrize("arm", ["control", "cascade", "s1", "guardian", "original"])
def test_no_kit_arm_pays_for_the_preflight(arm):
    """Kit arms have their own failure paths, none of this shape. A per-trial container round-trip
    on every one of them to guard a hazard they do not have is cost with no return."""
    runner = _RecordingRunner(returncode=2)
    runner.preflight_gate(arm)  # must not raise
    assert runner.calls == []


# ── the re-exec ───────────────────────────────────────────────────────────────────────────────
def _run_gate_probe(arm: str, tmp_path: Path, *, make_python: bool) -> str:
    """Drive the real gate's re-exec decision in a subprocess, and report which interpreter ran."""
    fake = tmp_path / "python"
    if make_python:
        fake.write_text(f"#!{sys.executable}\nimport sys; print('REEXECED'); sys.exit(0)\n")
        fake.chmod(0o755)
    r = subprocess.run(
        [sys.executable, str(_PKG / "scripts/monitorkit_gate.py"), "--arms"],
        env={"PATH": "/usr/bin:/bin", "MONITORKIT_ARM": arm, "AME_PYTHON": str(fake),
             "AUTO_MODE_EVAL_SRC": str(tmp_path)},
        capture_output=True, text=True, timeout=120,
    )
    return r.stdout


def test_a_bridged_arm_re_execs_into_the_ame_interpreter(tmp_path):
    assert "REEXECED" in _run_gate_probe("ame_cascade", tmp_path, make_python=True)


def test_a_kit_arm_never_re_execs(tmp_path):
    """A kit arm's process must be the one it always was."""
    assert "REEXECED" not in _run_gate_probe("cascade", tmp_path, make_python=True)


def test_a_missing_interpreter_does_not_re_exec_and_does_not_raise(tmp_path):
    """It fails closed downstream instead — which is right, but is a denial on EVERY call, so the
    runner preflights rather than relying on it."""
    assert "REEXECED" not in _run_gate_probe("ame_cascade", tmp_path, make_python=False)


def test_the_re_exec_is_idempotent(tmp_path):
    """`os.execv` replaces the process, which re-enters the same function. Without the guard it
    execs forever and the tool call never returns."""
    fake = tmp_path / "python"
    fake.write_text(f"#!{sys.executable}\nimport sys; print('REEXECED'); sys.exit(0)\n")
    fake.chmod(0o755)
    r = subprocess.run(
        [sys.executable, str(_PKG / "scripts/monitorkit_gate.py"), "--arms"],
        env={"PATH": "/usr/bin:/bin", "MONITORKIT_ARM": "ame_cascade", "AME_PYTHON": str(fake),
             "_MONITORKIT_AME_REEXECED": "1"},
        capture_output=True, text=True, timeout=120,
    )
    assert "REEXECED" not in r.stdout
