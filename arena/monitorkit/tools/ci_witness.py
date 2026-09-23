#!/usr/bin/env python3
"""Decide whether a `pytest` run is EVIDENCE that the suite ran, or merely an exit code.

THE DEFECT THIS PREVENTS. A harness fails by producing a number, not by crashing. A
ten-arm campaign in this project completed with `status=success`, zero gate records and
results identical to the ungated control, because the gate was never in the path and the
guard against exactly that sat behind a condition that did not mention it. The same shape
is available to a test gate, and every variant of it is silent:

* `pytest` exits 5 when it collects nothing, and a `check` script that only tested for a
  non-zero status would report that faithfully -- but a `tests/` that stopped being
  collected (a renamed directory, a `conftest` that swallows collection, a wheel installed
  over the checkout) is a green run over an empty suite;
* `pytest.importorskip` turns a missing dependency into a dot on the screen. Two tests in
  this repository did exactly that until the dependency was declared: on the maintainer's
  interpreter they ran, on a clean checkout they vanished, and both printed "passed";
* a crash before the report is written leaves whatever report was there before, so the
  next reader inspects a previous run's evidence and calls it this one's.

So the gate does not ask "did pytest return 0". It asks the report how many tests ran, how
many were skipped, and whether the report is this run's at all -- and it fails CLOSED,
naming the reason, when the answer is missing.

Usage:
    ci_witness.py --report REPORT.xml --min-tests N --pytest-status RC
                  [--allow-skips REASON] [--label TEXT]
"""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ElementTree
from pathlib import Path

EXIT_OK = 0
EXIT_NO_WITNESS = 1


def _die(reason: str) -> int:
    print(f"witness: FAILED -- {reason}", file=sys.stderr)
    return EXIT_NO_WITNESS


def _totals(report: Path) -> dict[str, int]:
    """Sum the JUnit counters across every `<testsuite>` in the report.

    Summed rather than read off the first suite: `pytest` writes one suite today, and a
    reader that assumed that would silently drop all but the first if it ever writes more
    (`-p xdist`, a future default). Dropping suites lowers the count, which is the
    direction that turns a real regression into a passing floor check.
    """
    root = ElementTree.parse(report).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    if not suites:
        raise ValueError(f"no <testsuite> element in {report}")
    keys = ("tests", "failures", "errors", "skipped")
    return {k: sum(int(s.get(k, 0)) for s in suites) for k in keys}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path, help="pytest --junitxml path")
    parser.add_argument("--min-tests", required=True, type=int)
    parser.add_argument("--pytest-status", required=True, type=int)
    parser.add_argument(
        "--allow-skips",
        default="",
        help="a REASON, echoed. Empty means a skipped test fails the gate.",
    )
    parser.add_argument("--label", default="", help="printed with the witness line")
    args = parser.parse_args(argv)

    # The report first, THEN the exit status. A missing report with status 0 is the
    # dangerous combination -- "success" with no evidence -- and reporting the status
    # first would hide it behind the more obvious failure whenever both are wrong.
    if not args.report.exists():
        return _die(
            f"pytest wrote no report at {args.report}: it did not run. "
            f"(its exit status was {args.pytest_status}, which on its own proves nothing)"
        )
    if args.report.stat().st_size == 0:
        return _die(
            f"the report at {args.report} is empty: pytest died before writing it "
            f"(exit status {args.pytest_status}). An empty file is not a passing run."
        )
    try:
        totals = _totals(args.report)
    except (ElementTree.ParseError, ValueError) as exc:
        return _die(f"the report at {args.report} is not a readable JUnit report: {exc}")

    ran = totals["tests"]
    skipped = totals["skipped"]
    executed = ran - skipped
    label = f" [{args.label}]" if args.label else ""

    if ran == 0:
        return _die(
            "the report records 0 tests. A suite that stopped being collected reports "
            "the same green as a suite that passed."
        )
    if executed < args.min_tests:
        return _die(
            f"only {executed} tests executed ({ran} collected, {skipped} skipped); the "
            f"floor is {args.min_tests}. This is a tripwire for a suite that quietly "
            f"stopped being collected, not a coverage target -- if the suite really did "
            f"shrink, lower MONITORKIT_MIN_TESTS in ./check in the same commit."
        )
    if totals["failures"] or totals["errors"]:
        return _die(f"{totals['failures']} failed, {totals['errors']} errored")
    if skipped and not args.allow_skips:
        return _die(
            f"{skipped} test(s) skipped. A skip is a test that did not run reported as a "
            f"test that passed; the usual cause is an undeclared dependency reached "
            f"through pytest.importorskip. Install it, delete the test, or run with "
            f"MONITORKIT_ALLOW_SKIPS='<reason>' -- the reason is required and is echoed."
        )
    if args.pytest_status != 0:
        return _die(
            f"pytest exited {args.pytest_status} while its report shows no failure. "
            f"Something outside the tests went wrong (a plugin, a collection error, an "
            f"internal error); the status is authoritative."
        )

    if skipped:
        print(f"witness: {skipped} skip(s) ALLOWED -- {args.allow_skips}", file=sys.stderr)
    print(f"witness{label}: {executed} tests executed, {skipped} skipped, 0 failed")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
