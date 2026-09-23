"""World-build (materialize/bringup) transient-vs-broken classification (hardening).

A TRANSIENT docker/daemon/exec flake at world-build must become a retriable `transport` EXCLUDE (the
sweep resamples it), while a genuinely broken world (missing snapshot tarball, world-guard rc,
sink-verify rc) must stay a non-retriable materialize_failed/bringup_failed fail-close (D-4c). The
discriminator is the safety-critical part: too broad launders broken worlds into resamples and
re-opens the D-4c fail-quiet, so it is a vetted whitelist, tested directly here.
"""
from __future__ import annotations

from rollout.runner import _is_transient_world_fault, _RETRIABLE_ABORT_CLASSES


def test_sigkill_is_transient():
    # rc 137 (SIGKILL of the exec: OOM/kill) is transport, same rule as the agent-side 137.
    assert _is_transient_world_fault(137, "Killed") is True


def test_docker_daemon_and_exec_flakes_are_transient():
    for msg in (
        "error during connect: Get http://%2Fvar%2Frun%2Fdocker.sock/...: EOF",
        "Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
        "No such exec instance: abc123",
        "No such container: worldsvc",
        "read tcp 10.0.0.2:22->10.0.0.3:2375: connection reset by peer",
    ):
        assert _is_transient_world_fault(1, msg) is True, msg


def test_genuinely_broken_world_is_NOT_transient():
    # the failure modes that MUST stay fail-closed — never laundered into a resample (the D-4c hazard)
    for rc, msg in (
        (1, "tar: repo_snapshot.tar.gz: Cannot open: No such file or directory"),
        (4, "world-guard: expected asset missing"),
        (3, "sink-verify: endpoint returned 500"),
        (2, "python: SyntaxError in seed script"),
        (1, ""),  # a bare non-zero with no signature is a broken world, not transient
    ):
        assert _is_transient_world_fault(rc, msg) is False, (rc, msg)


def test_transient_maps_to_a_retriable_class_and_the_fail_close_classes_do_not():
    # the class the call sites hand a transient fault is retriable; the fail-close classes are not,
    # so a whitelisted flake resamples while a broken world drops out of the denominator as designed.
    assert "transport" in _RETRIABLE_ABORT_CLASSES
    assert "materialize_failed" not in _RETRIABLE_ABORT_CLASSES
    assert "bringup_failed" not in _RETRIABLE_ABORT_CLASSES
