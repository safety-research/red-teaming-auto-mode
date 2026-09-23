"""The gate's own gate: tests that the thing which runs the tests is really wired up.

WHY THIS FILE EXISTS. Everything else in this suite tests the library. Nothing tested the
machinery that decides whether the suite runs at all -- and that machinery fails silently
by construction. A workflow that never triggers, a `./check --ci` that stopped invoking
pytest, a `--ci` flag renamed out from under `.github/workflows/check.yml`, a wheel
shadowing the checkout so 600 green tests describe code nobody edited: every one of those
looks exactly like a healthy repository from the outside. The governing lesson of this
project is that a harness fails by producing a number, not by crashing.

So each test below answers "if this were broken, what would I see?" with something other
than "the same green I see now".

AND THEY READ THE WORKFLOW AS STRUCTURE, NOT AS TEXT. The first version of this file matched
strings against `check.yml`, and string matching cannot tell a step's cosmetic `name:` from
the `run:` that executes. With `name: ./check --ci` on the step, `run:` could be changed to
`echo skipping`, to `uv run pytest`, or to `./check` with no witness at all, and every test
here stayed green — the gate removed from the path, and the guard against exactly that
satisfied by a label. Text also cannot notice a workflow that no longer PARSES, and an
invalid workflow file is one GitHub never runs: the same silence as having no CI. Anything
that decides whether the gate executes is therefore asserted against the parsed document;
raw text is used only where the question really is "does this token appear anywhere".
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "check"
WITNESS = ROOT / "tools" / "ci_witness.py"
WORKFLOW = ROOT / ".github" / "workflows" / "check.yml"
PRE_PUSH = ROOT / ".githooks" / "pre-push"
PYPROJECT = ROOT / "pyproject.toml"

#: The exact command every caller of the gate must use. Spelled once, here, so that a
#: rename has to pass through this constant and cannot leave one caller behind.
GATE_COMMAND = "./check --ci"


def _uncommented(text: str) -> list[str]:
    """Lines whose first non-space character is not `#`.

    YAML comments are prose, and this file's prose necessarily quotes the very tokens the
    tests below forbid. Scanning raw text would make the workflow's own explanation of why
    it has no conditionals fail the test that forbids conditionals.
    """
    return [line for line in text.splitlines() if not line.lstrip().startswith("#")]


def _workflow_body() -> str:
    return "\n".join(_uncommented(WORKFLOW.read_text(encoding="utf-8")))


def _workflow() -> dict[str, Any]:
    """The workflow as GitHub reads it: a parsed document.

    Every question about what CI actually DOES is answered from here rather than from the
    file's text, because a step's `name` and its `run` are the same characters to a regex
    and opposite things to a runner.
    """
    parsed = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(parsed, dict), f"{WORKFLOW.name} is not a YAML mapping"
    return parsed


def _triggers() -> dict[str, Any]:
    """The `on:` block.

    Keyed by `True`, not `"on"`, when the key is unquoted: YAML 1.1 — which is what PyYAML
    implements — reads a bare `on` as the boolean. GitHub's own parser does not, so the file
    is correct and the reader has to know. Looking up only `"on"` would silently find
    nothing and turn "the workflow has no triggers" into a passing test.
    """
    workflow = _workflow()
    for key in ("on", True):
        if key in workflow:
            return workflow[key] or {}
    raise AssertionError("the workflow declares no `on:` block, so nothing ever triggers it")


def _steps() -> list[dict[str, Any]]:
    return [
        step
        for job in _workflow().get("jobs", {}).values()
        for step in (job.get("steps") or [])
    ]


def _lines_of(step: dict[str, Any]) -> list[str]:
    """The command lines one step executes, comments and blanks dropped.

    A `name:`, an `env:` value and a YAML comment are all absent from this by construction,
    which is the entire point.
    """
    script = step.get("run")
    if not isinstance(script, str):
        return []
    return [
        line.strip()
        for line in script.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _run_lines() -> list[str]:
    """Every command line CI executes, across every step."""
    return [line for step in _steps() for line in _lines_of(step)]


def _keys_named(node: Any, name: str, path: str = "") -> list[str]:
    """Locations of every mapping key `name`, at any depth.

    Recursive and structural so that a key cannot hide from it by being quoted, indented
    unusually, or attached to the job instead of the step — three spellings of the same
    thing that a line-oriented regex sees as three different problems and catches one of.
    """
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}.{key}"
            if str(key) == name:
                found.append(f"{here} = {value!r}")
            found += _keys_named(value, name, here)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found += _keys_named(value, name, f"{path}[{index}]")
    return found


# ══ the workflow exists, triggers, and runs the gate ══════════════════════════════════
def test_the_workflow_file_is_where_github_looks_for_it():
    """A workflow in any other directory is a text file. GitHub reads exactly
    `.github/workflows/*.yml`, and nothing reports a workflow that was never found."""
    assert WORKFLOW.is_file(), f"no workflow at {WORKFLOW.relative_to(ROOT)}"


def test_the_workflow_parses_because_one_that_does_not_is_never_run():
    """An unparseable workflow does not fail the build -- it produces no build. GitHub
    reports it as an error on the file and every push after it sails through, which from
    the repository's side is indistinguishable from CI having been deleted.

    Nothing else here would notice: a broken indent leaves every string the other tests
    match on exactly where it was. Verified by breaking the indentation deliberately -- the
    text-matching suite stayed green.
    """
    workflow = _workflow()
    assert workflow.get("jobs"), "the workflow declares no jobs, so it runs nothing"
    for name, job in workflow["jobs"].items():
        assert job.get("steps"), f"job {name!r} has no steps"


def test_the_workflow_triggers_on_both_events_the_gate_is_for():
    """`push` alone leaves pull requests from a fork unchecked; `pull_request` alone leaves
    a direct push to the default branch unchecked. The gap is invisible either way -- there
    is no red build, there is no build."""
    triggers = _triggers()
    for event in ("push", "pull_request"):
        assert event in triggers, (
            f"the workflow does not trigger on {event} (it triggers on: {sorted(triggers)})"
        )


def test_a_step_actually_runs_the_gate_and_a_step_merely_NAMED_for_it_does_not_count():
    """A CI job that lists pytest steps of its own drifts from `./check`, and the drift
    surfaces as an argument about whether CI is trustworthy rather than as a failure.

    THE DEFECT THIS PREVENTS, WHICH THE PREVIOUS VERSION OF THIS TEST DID NOT. It asserted
    the string `./check --ci` appeared somewhere in the file -- and it does, in the step's
    `name:`. Replacing that step's `run:` with `echo skipping`, with `uv run pytest`, or
    with `./check` (no `--ci`: no witness, no skip check, no collection floor) left all
    twenty-five tests green while CI stopped running the gate. Only the executed lines
    count now.

    The command must stand alone on its line. A trailing comment makes this fail, which is
    the safe direction: `run: ./check --tests  # was ./check --ci` used to pass.
    """
    assert GATE_COMMAND in _run_lines(), (
        f"no step EXECUTES `{GATE_COMMAND}`. Lines CI actually runs: {_run_lines()}"
    )


def test_every_check_invocation_in_the_workflow_is_a_command_check_actually_has():
    """THE RENAME TRAP. `./check --ci` in a workflow is a string; nothing links it to the
    script. Rename the flag and CI keeps running -- against a script that now errors, or,
    worse, against one that grew a lenient default. This is the link, and it is checked on
    the machine of whoever does the renaming, before the push.

    Read from the executed lines, for the reason in the test above: an invocation in a step
    name is not an invocation.
    """
    supported = subprocess.run(
        [str(CHECK), "--commands"], capture_output=True, text=True, check=True, cwd=ROOT
    ).stdout.split()
    invoked = re.findall(r"\./check((?:\s+-{1,2}[\w-]+)*)", "\n".join(_run_lines()))
    assert invoked, "the workflow invokes ./check nowhere"
    for arguments in invoked:
        for argument in arguments.split():
            assert argument in supported, (
                f"the workflow runs `./check {argument}`, which ./check does not support "
                f"(it supports: {' '.join(supported)})"
            )


def test_the_gate_script_is_executable_in_the_checkout():
    """`run: ./check --ci` on a file without the mode bit is "Permission denied" on a
    runner and nowhere else, and the mode bit is a thing git can lose in a rewrite."""
    assert os.access(CHECK, os.X_OK), "check is not executable; CI would fail to invoke it"


# ══ the workflow cannot pass without running ══════════════════════════════════════════
@pytest.mark.parametrize(
    "token,why",
    [
        ("continue-on-error", "a step that cannot fail the build is not a gate"),
        ("|| true", "swallowing the exit status turns any failure into a pass"),
        ("MONITORKIT_SKIP_CHECK", "the push-hook bypass must not be reachable from CI"),
        ("MONITORKIT_ALLOW_SKIPS", "skips must not be blanket-allowed by the runner"),
        ("MONITORKIT_MIN_TESTS", "the collection floor must not be lowered by the runner"),
    ],
)
def test_the_workflow_carries_no_way_to_pass_without_running(token, why):
    assert token not in _workflow_body(), f"{token!r} in the workflow: {why}"


def test_no_step_in_the_workflow_sits_behind_a_condition():
    """THE FAILURE THIS PROJECT ALREADY PAID FOR. Ten arms of a nine-hour campaign reported
    `status=success` with zero gate records, because the guard against exactly that sat
    behind a condition that did not mention it. A conditional gate's green means "the
    condition was false", and nothing distinguishes that from "the tests passed".

    Should a condition ever be genuinely necessary, deleting this test is the honest way to
    add one -- it forces the decision to be written down.

    Structural, over the parsed document, because the line-oriented predecessor matched
    `(^|\\s)if:` and a quoted key -- `"if": ''`, legal YAML and legal Actions -- walked past
    it. The walk finds the key wherever it is: on the workflow, on the job, on a step.
    """
    offenders = _keys_named(_workflow(), "if")
    assert not offenders, f"conditional in the gate workflow: {offenders}"


# ══ the workflow tests the version that ships ═════════════════════════════════════════
def test_the_matrix_covers_the_python_floor_the_package_declares():
    """A green CI on 3.13 says nothing about 3.12, and 3.12 is what `requires-python`
    promises and what the evaluation sandbox image (`python:3.12-slim`) runs. That gap was
    real: `Path.resolve()` raises on a symlink cycle on 3.12 and returns the path on 3.13,
    so two router tests asserting the documented fail-open passed on every run and would
    have failed in the image. Nothing had ever run the suite on the floor.
    """
    declared = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["requires-python"]
    floor = declared.lstrip(">=~^ ").split(",")[0].strip()
    matrices = [
        job["strategy"]["matrix"]["python-version"]
        for job in _workflow()["jobs"].values()
        if "python-version" in (job.get("strategy") or {}).get("matrix", {})
    ]
    assert matrices, "the workflow declares no python-version matrix"
    versions = [str(v) for m in matrices for v in m]
    assert floor in versions, (
        f"requires-python says >={floor} but CI runs {versions}. Either test the floor or "
        f"stop claiming it."
    )


def test_each_matrix_leg_is_made_to_prove_which_interpreter_it_ran():
    """A matrix is the one arrangement whose broken state looks exactly like its working
    state: two legs, both green, both the same interpreter. `uv sync` resolves a Python by
    its own rules, so the leg has to be pinned when it is built AND checked when it runs.

    The declaration is read off the step that RUNS the gate, not off the file: an
    `MONITORKIT_EXPECT_PYTHON` attached to some other step pins nothing, and to a text
    search over the whole document the two are the same characters.
    """
    gate_steps = [step for step in _steps() if GATE_COMMAND in _lines_of(step)]
    assert gate_steps, f"no step runs `{GATE_COMMAND}`"
    for step in gate_steps:
        declared = (step.get("env") or {}).get("MONITORKIT_EXPECT_PYTHON")
        assert declared == "${{ matrix.python-version }}", (
            "the step that runs the gate does not declare which interpreter the leg must "
            f"be (MONITORKIT_EXPECT_PYTHON={declared!r})"
        )
    assert any('--python "${{ matrix.python-version }}"' in line for line in _run_lines()), (
        "uv sync is free to pick an interpreter other than the leg's"
    )


def test_the_environment_ci_builds_is_the_one_the_lockfile_describes():
    """`uv sync` without `--locked` resolves whatever satisfies pyproject.toml at the moment
    it runs, so a dependency added and never locked gives CI a different environment than
    the developer has -- and reports green about it. `--locked` turns that into a red build
    carrying its own fix. Removing it changes nothing anyone can see, which is the only
    reason this is a test."""
    syncs = [line for line in _run_lines() if line.startswith("uv sync")]
    assert syncs, "CI never installs the dependency group it then tests against"
    for line in syncs:
        assert "--locked" in line, f"`{line}` may resolve something the lockfile does not"


def test_the_gate_refuses_to_run_as_an_interpreter_it_was_not_told_it_was(tmp_path):
    """And the declaration is enforced, not decorative. Checked before pytest, so the leg
    that is lying costs a second rather than a suite.

    RUN AGAINST A COPY OF `check`, over a one-test suite, and that is not incidental. The
    first version of this test invoked the real gate -- which runs this suite, which runs
    this test. The pin was the only thing making that finite, so the test's own subject was
    also its only bound: delete the pin and it re-enters the whole gate without end,
    measured past two minutes. A hang is not a red.

    Bounding the WAIT does not fix it either, which was measured rather than reasoned:
    giving the child its own process group and killing the group on timeout left 207
    descendants alive and still multiplying, because each level opens a session of its own
    and escapes the group its parent could kill. A runaway cannot be cleaned up from
    outside. The copy has no recursion to bound: the pin is examined before pytest, so the
    path under test is identical, and the suite it would go on to run is one trivial test.
    """
    home = _gate_copy(tmp_path)
    result = _run_gate(home, MONITORKIT_EXPECT_PYTHON="9.9")
    assert result.returncode != 0
    assert "declared to be Python 9.9" in result.stderr, (
        f"the gate did not refuse an interpreter it cannot be. It said: {result.stderr!r}"
    )


def test_the_gate_refuses_to_run_inside_itself_without_end(tmp_path):
    """The bound of last resort, for the day a test invokes the real gate again.

    Nothing in this suite does today -- every invocation goes through `_gate_copy` -- and
    that arrangement is one careless edit from being untrue, at which point the failure is
    the unrecoverable kind: 207 processes survived being killed by group, because each level
    had started its own session. `check` counts its own nesting and refuses, which turns
    that mistake into a message naming the missing bound instead of a machine to reboot.
    """
    home = _gate_copy(tmp_path)
    result = _run_gate(home, MONITORKIT_CHECK_DEPTH="9")
    assert result.returncode != 0, "the gate ran as its own tenth nested invocation"
    assert "inside itself" in result.stderr


# ══ the local gate and the remote gate are one gate ═══════════════════════════════════
def _hook_repo(tmp_path: Path) -> tuple[Path, Path]:
    """A throwaway git repository holding the real hook and a `check` that only records.

    The hook is EXECUTED rather than read, because reading it cannot distinguish the command
    from prose about the command -- and this hook's header, its progress line and its
    failure text all quote `./check --ci`. Replacing the one line that invokes it with
    `if false; then` left the string in four places and the old test green: a push hook that
    verified nothing and said so nowhere.

    A stub stands in for the real gate so this costs milliseconds and so the recorded
    arguments are the assertion -- running the true gate here would also re-enter this
    suite.
    """
    repo = tmp_path / "repo"
    (repo / ".githooks").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)
    shutil.copy2(PRE_PUSH, repo / ".githooks" / "pre-push")
    stub = repo / "check"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        'printf "%s\\n" "$*" >> "$(dirname "$0")/invoked.log"\n'
        'exit "${STUB_CHECK_EXIT:-0}"\n',
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return repo, repo / "invoked.log"


def _run_hook(repo: Path, **env: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(repo / ".githooks" / "pre-push")],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=60,
        stdin=subprocess.DEVNULL,
        # MONITORKIT_SKIP_CHECK is cleared unless a case sets it: a developer who exported
        # the bypass in their shell would otherwise have these tests pass without the hook
        # ever reaching the gate -- the bypass bypassing its own test.
        env={**os.environ, "MONITORKIT_SKIP_CHECK": "", **env},
    )


def test_the_pre_push_hook_runs_exactly_what_ci_runs(tmp_path):
    """Two gates that differ produce a class of change that passes locally and fails
    remotely (or the reverse, which is worse), and the usual repair is to trust neither.

    Asserted on what the hook INVOKED. `./check` with no `--ci` would satisfy any reading
    of the file and would skip the witness entirely.
    """
    repo, log = _hook_repo(tmp_path)
    result = _run_hook(repo)
    assert result.returncode == 0, result.stderr
    assert log.exists(), "the hook completed without ever invoking ./check"
    invoked = [line for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert invoked == [GATE_COMMAND.removeprefix("./check ")], (
        f"the hook invoked ./check with {invoked}, not `{GATE_COMMAND}`"
    )


def test_the_pre_push_hook_refuses_the_push_when_the_gate_fails(tmp_path):
    """The invocation is only half of it: a hook that runs the gate and ignores its exit
    status is a hook that reports every push as checked."""
    repo, _ = _hook_repo(tmp_path)
    result = _run_hook(repo, STUB_CHECK_EXIT="1")
    assert result.returncode != 0, "the hook allowed a push whose gate had failed"
    assert "REFUSED" in result.stderr


def test_the_pre_push_bypass_needs_a_reason_and_announces_itself(tmp_path):
    """The documented escape hatch, held to its documentation: it skips the gate, and it
    cannot be taken quietly. A bypass that prints nothing becomes the way everyone pushes."""
    repo, log = _hook_repo(tmp_path)
    result = _run_hook(repo, MONITORKIT_SKIP_CHECK="docs-only change")
    assert result.returncode == 0
    assert "docs-only change" in result.stderr
    assert not log.exists(), "the bypass was taken and the gate ran anyway"


# ══ the suite is testing the checkout ═════════════════════════════════════════════════
def test_the_package_under_test_is_this_checkout_and_not_an_installed_copy():
    """`uv sync` installs monitorkit into `.venv`, so two importable copies exist whenever
    the gate runs. If the checkout ever stopped winning, every test here would keep passing
    -- against the last-installed bytes -- and an edit to `src/` would change nothing at
    all.

    WHAT THIS DOES NOT PROVE, since the docstring used to claim it: it is not a witness for
    `./check` prepending `src` to PYTHONPATH. `uv sync` installs the project EDITABLE -- a
    `.pth` pointing back at this same `src` -- so the assertion holds with the prepend
    removed (checked). What it does catch is the case that actually bites: a real, stale,
    non-editable copy of the package winning the import.
    """
    import monitorkit

    imported = Path(monitorkit.__file__).resolve()
    expected = ROOT / "src" / "monitorkit"
    assert imported.parent == expected, f"imported {imported}, expected a file under {expected}"


# ══ the witness itself ════════════════════════════════════════════════════════════════
def _report(tmp_path: Path, *, tests: int, failures: int = 0, errors: int = 0, skipped: int = 0):
    path = tmp_path / "report.xml"
    path.write_text(
        '<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest" '
        f'errors="{errors}" failures="{failures}" skipped="{skipped}" tests="{tests}" '
        'time="1.0"></testsuite></testsuites>',
        encoding="utf-8",
    )
    return path


def _run_witness(report: Path, *, status: int = 0, floor: int = 10, allow: str = ""):
    return subprocess.run(
        [
            sys.executable, str(WITNESS),
            "--report", str(report),
            "--min-tests", str(floor),
            "--pytest-status", str(status),
            "--allow-skips", allow,
        ],
        capture_output=True,
        text=True,
    )


def test_the_witness_passes_a_healthy_run_and_says_what_it_saw(tmp_path):
    result = _run_witness(_report(tmp_path, tests=600))
    assert result.returncode == 0, result.stderr
    assert "600 tests executed" in result.stdout


def test_the_witness_fails_when_the_report_is_absent(tmp_path):
    """The dangerous combination: exit status 0 and no evidence. This is the campaign's
    failure mode expressed in one file that was never written."""
    result = _run_witness(tmp_path / "never-written.xml")
    assert result.returncode != 0
    assert "did not run" in result.stderr


def test_the_witness_fails_on_a_report_that_was_created_but_never_filled(tmp_path):
    """`mktemp` makes the file before pytest runs, so "exists" is not "was written". A
    crash between the two leaves precisely this."""
    empty = tmp_path / "empty.xml"
    empty.write_text("", encoding="utf-8")
    result = _run_witness(empty)
    assert result.returncode != 0
    assert "empty" in result.stderr


def test_the_witness_fails_when_nothing_was_collected(tmp_path):
    result = _run_witness(_report(tmp_path, tests=0), floor=0)
    assert result.returncode != 0
    assert "0 tests" in result.stderr


def test_the_witness_fails_when_the_suite_shrank_below_the_floor(tmp_path):
    """A renamed directory or a broken conftest collects a handful of tests and passes.
    The floor is the tripwire, and its failure names itself as a tripwire so nobody
    "fixes" it by deleting it."""
    result = _run_witness(_report(tmp_path, tests=9), floor=500)
    assert result.returncode != 0
    assert "floor is 500" in result.stderr


def test_the_witness_fails_on_a_skip_and_names_the_mechanism(tmp_path):
    """A skip is a test that did not run, reported as a test that passed. Two of this
    repository's own tests did that for a week."""
    result = _run_witness(_report(tmp_path, tests=600, skipped=2))
    assert result.returncode != 0
    assert "importorskip" in result.stderr


def test_a_skip_can_be_allowed_only_with_a_reason_that_is_echoed(tmp_path):
    """An allowance with no reason is a default in waiting; one that prints itself on every
    run is a decision somebody has to keep defending."""
    result = _run_witness(_report(tmp_path, tests=600, skipped=2), allow="no SDK on this leg")
    assert result.returncode == 0, result.stderr
    assert "no SDK on this leg" in result.stderr


def test_the_witness_fails_a_failing_run_even_if_the_status_were_lost(tmp_path):
    """Belt and braces: the report and the exit status are independent channels, and the
    gate fails if EITHER says so. A wrapper that swallowed the status is common; a wrapper
    that also rewrites the XML is not."""
    result = _run_witness(_report(tmp_path, tests=600, failures=1), status=0)
    assert result.returncode != 0
    assert "1 failed" in result.stderr


def test_the_witness_fails_a_nonzero_status_even_when_the_report_is_clean(tmp_path):
    """Collection errors, internal errors and plugin crashes can leave a report that
    describes only the tests that got as far as running."""
    result = _run_witness(_report(tmp_path, tests=600), status=2)
    assert result.returncode != 0
    assert "exited 2" in result.stderr


# ══ the gate and the witness, wired together ══════════════════════════════════════════
def _gate_copy(tmp_path: Path) -> Path:
    """A copy of the gate -- `check` and its witness -- over a one-test suite.

    EVERY test here that runs the gate runs this copy, and none runs the real one. The real
    gate runs this suite, so a test that invoked it would re-enter the gate, which would run
    the test, without end; that is not a hypothetical, it was the arrangement until it was
    measured. The scripts are copied byte for byte, so the code under test is the same code
    -- only the suite underneath it is one trivial test instead of six hundred.
    """
    home = tmp_path / "gate"
    (home / "tests").mkdir(parents=True)
    (home / "tools").mkdir()
    shutil.copy2(CHECK, home / "check")
    shutil.copy2(WITNESS, home / "tools" / "ci_witness.py")
    (home / "tests" / "test_only.py").write_text("def test_only():\n    pass\n", encoding="utf-8")
    return home


def _run_gate(home: Path, **env: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(home / "check"), "--ci"],
        cwd=home,
        capture_output=True,
        text=True,
        timeout=300,
        env={
            **os.environ,
            "PYTHON": sys.executable,     # the copy has no .venv of its own
            "MONITORKIT_MIN_TESTS": "1",  # its suite is one test, on purpose
            "MONITORKIT_ALLOW_SKIPS": "",
            "CI": "1",                    # silence the hook advice; there is no clone here
            **env,
        },
    )


def test_the_gate_fails_when_pytest_dies_before_it_can_report(tmp_path):
    """THE WIRING, end to end: `check` invokes the witness, and the witness's verdict
    reaches the caller's exit status.

    The witness's own failure modes were each covered above; that it is CONNECTED was not,
    and connection is the part that failed in the campaign this repository is named after.
    Measured: delete the one line in `do_ci` that tests the witness's return value and
    `./check --ci` exits 0 on a suite with two failing tests, after printing
    "witness: FAILED -- 2 failed" to stderr. That mutation fails this test.

    Both halves are asserted, because a copy that could not pass a healthy run would
    prove nothing by failing an unhealthy one.

    WHAT THIS DOES NOT PROVE, having been checked rather than assumed: it is not a witness
    for the report being freshly allocated. Replacing `mktemp` with a fixed path -- with or
    without the `rm -f` that follows -- still fails this scenario, because the witness is
    given pytest's exit status as an independent channel and refuses a non-zero one whatever
    the report says. `mktemp` is defence in depth behind that, and remains uncovered.
    """
    home = _gate_copy(tmp_path)

    healthy = _run_gate(home)
    assert healthy.returncode == 0, f"the copied gate cannot pass a good run:\n{healthy.stderr}"
    assert "1 tests executed" in healthy.stdout

    # pytest now dies during collection, before it can write any report at all.
    (home / "tests" / "conftest.py").write_text("import os\n\nos._exit(3)\n", encoding="utf-8")
    crashed = _run_gate(home)
    assert crashed.returncode != 0, (
        "the gate reported success for a run in which pytest wrote no report at all"
    )
    assert "witness: FAILED" in crashed.stderr


def test_a_failing_test_reaches_the_exit_status_of_the_gate(tmp_path):
    """The plainest thing a gate must do, asserted because it was one deleted line away from
    not being true, and because nothing else in this suite runs `./check --ci` over a suite
    that fails. `do_ci` now refuses on the witness's verdict AND on pytest's own status;
    either alone is enough, so no single edit can quietly restore exit 0."""
    home = _gate_copy(tmp_path)
    (home / "tests" / "test_only.py").write_text(
        "def test_only():\n    assert False, 'this must reach the caller'\n", encoding="utf-8"
    )
    result = _run_gate(home)
    assert result.returncode != 0, "the gate exited 0 over a failing test"


def test_a_skipped_test_reaches_the_exit_status_of_the_gate(tmp_path):
    """The channel the exit status alone cannot see, end to end.

    `pytest` exits 0 for a skip, and for a suite that shrank to nothing collectable above
    zero: on those the WITNESS's verdict is the only thing standing between a vanished test
    and a green gate. That is what makes it worth invoking, and this is the assertion that
    its verdict is still consulted -- deleting the line in `do_ci` that reads it leaves
    every other end-to-end case here passing, because pytest's own status covers them.
    """
    home = _gate_copy(tmp_path)
    (home / "tests" / "test_only.py").write_text(
        'import pytest\n\n\ndef test_only():\n    pytest.skip("an undeclared dependency")\n',
        encoding="utf-8",
    )
    result = _run_gate(home)
    assert result.returncode != 0, "the gate exited 0 over a test that never ran"
    assert "skipped" in result.stderr
