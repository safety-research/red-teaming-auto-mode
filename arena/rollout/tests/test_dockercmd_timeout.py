"""The enforced-ceiling contract for `rollout.dockercmd` — the regression test for the wedge.

On 2026-07-27 a compose client outlived its launcher by 15 days. The mechanism was not exotic:
`docker` forks the compose plugin as a child, `subprocess.run(timeout=)` kills only the direct
child, and the grandchild reparents to init and runs forever. These tests reproduce that shape
with `sh` standing in for the client and a background `sleep` standing in for the plugin, then
assert that `run_docker` reaps the whole tree.

No Docker required — that is the point. This runs in the offline gate.
"""

from __future__ import annotations

import os
import signal
import subprocess
import tempfile
import time

import pytest

from rollout.dockercmd import DockerTimeout, docker_endpoint, run_docker


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wedge(sleep_s: int) -> tuple[str, str]:
    """A shell that forks a long-lived grandchild and records its pid to a temp pidfile."""
    with tempfile.NamedTemporaryFile("r+", suffix=".pid", delete=False) as fh:
        pidfile = fh.name
    return f"sleep {sleep_s} & echo $! > {pidfile}; sleep {sleep_s}", pidfile


def _learn_grandchild_pid(pidfile: str) -> int | None:
    """Poll the pidfile the wedge writes, then remove it and return the grandchild pid."""
    grandchild = None
    for _ in range(50):
        try:
            txt = open(pidfile).read().strip()
        except OSError:
            txt = ""
        if txt:
            grandchild = int(txt)
            break
        time.sleep(0.05)
    os.unlink(pidfile)
    return grandchild


def test_timeout_kills_the_grandchild_not_just_the_direct_child():
    """The whole point of the module. `subprocess.run(timeout=)` fails this; `run_docker` passes."""
    # Run it detached first to learn the grandchild pid, via a temp file the shell writes.
    script, pidfile = _wedge(600)

    with pytest.raises(DockerTimeout) as ei:
        run_docker(["sh", "-c", script], hard_s=1.5, label="fake-compose")

    # Give the group kill a moment to land.
    grandchild = _learn_grandchild_pid(pidfile)

    assert grandchild is not None, "test setup failed: never learned the grandchild pid"
    for _ in range(60):          # the SIGTERM->grace->SIGKILL ladder needs a beat
        if not _alive(grandchild):
            break
        time.sleep(0.1)
    assert not _alive(grandchild), (
        f"grandchild {grandchild} survived the timeout — this is the 15-day-orphan bug: "
        "the process GROUP was not killed"
    )
    assert "fake-compose" in str(ei.value)
    assert ei.value.hard_s == 1.5


def test_subprocess_run_alone_leaks_the_grandchild():
    """Documents WHY the module exists: the stdlib call the harness used to make leaks.

    If this ever starts failing, CPython changed its semantics and `run_docker`'s process-group
    machinery may be redundant. It is not redundant today.
    """
    script, pidfile = _wedge(30)
    try:
        subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=1.0)
    except subprocess.TimeoutExpired:
        pass
    grandchild = _learn_grandchild_pid(pidfile)
    assert grandchild is not None
    leaked = _alive(grandchild)
    # Clean up our own mess regardless of the assertion outcome.
    if leaked:
        try:
            os.kill(grandchild, signal.SIGKILL)
        except ProcessLookupError:
            pass
    assert leaked, "stdlib subprocess.run no longer leaks grandchildren — re-evaluate dockercmd"


def test_hard_s_is_keyword_only_and_has_no_default():
    """A new call site cannot silently inherit 'wait forever'."""
    with pytest.raises(TypeError):
        run_docker(["true"])                      # type: ignore[call-arg]
    with pytest.raises(TypeError):
        run_docker(["true"], 5)                   # type: ignore[misc]
    with pytest.raises(ValueError):
        run_docker(["true"], hard_s=0, label="x")


def test_success_path_returns_a_completedprocess():
    r = run_docker(["sh", "-c", "echo out; echo err >&2; exit 3"], hard_s=10, label="ok")
    assert r.returncode == 3
    assert r.stdout.strip() == "out"
    assert r.stderr.strip() == "err"


def test_swallow_timeout_returns_instead_of_raising():
    """Teardown must never replace the exception that actually ended the run."""
    r = run_docker(["sh", "-c", "sleep 30"], hard_s=1.0, label="teardown",
                   swallow_timeout=True)
    assert r.returncode == -9


def test_docker_endpoint_reports_docker_host(monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "ssh://vm-1")
    assert docker_endpoint() == "ssh://vm-1"
    monkeypatch.delenv("DOCKER_HOST")
    assert docker_endpoint().startswith("local:")
