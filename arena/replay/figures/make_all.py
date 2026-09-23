#!/usr/bin/env python3
"""Regenerate EVERY paper figure from committed data, in one run.

    python replay/figures/make_all.py                  # all figures
    python replay/figures/make_all.py --only pareto    # just one
    python replay/figures/make_all.py --list           # what exists, and where its data is
    python replay/figures/make_all.py --extract        # re-derive data/*.json from the raw
                                                      # sources first, then plot ("front to end")

Design contract (the thing this pipeline exists to fix):

  * A figure builder may NOT contain a measured number. Every value is read from
    ``replay/figures/data/<figure>.json``, and every record in those files carries a
    ``source`` naming the file it came from.
  * If an input is not on disk the figure FAILS LOUDLY, naming the missing file.
    A loud missing figure is correct; an invented one is not.
  * ``--extract`` is the only step that reaches outside this repo -- into
    $REPLAY_FIGURE_SOURCE (the rescued run tree). The committed JSON is the portable
    record, so plotting works without it.

Run with replay's own venv, which pins matplotlib exactly (see pyproject `plot` group):
    (cd replay && uv sync) && replay/.venv/bin/python replay/figures/make_all.py
Some EXTRACTORS need a module replay's plotting venv does not have (`simulation_grid`
needs `yaml`); --extract finds an interpreter that has it, or takes --extract-python <path>.
"""
from __future__ import annotations

import argparse
import importlib
import subprocess
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import figlib

# figure name -> (builder module, one-line intent)
FIGURES: dict[str, str] = {
    "injection_exists": "attacker climb curves (running-best ASR vs iteration), "
                        "text/JSON-L x informed/blind",
    # injection_serialization FIRST: ladder_robustness cross-checks its endpoints against that
    # file, so extracting in this order means the check has something to check on a clean tree.
    # The check is skipped-with-a-note rather than fatal when it is still absent, so
    # `--extract --only ladder_robustness` on a bare checkout also works.
    "injection_serialization": "the same ASR endpoint swept across ALL 26 measured "
                               "serialisations (the ladder is 5 of these rows)",
    "ladder_robustness": "THE ladder: the five rungs only, in ladder order, "
                         "AUC-ASR and final ASR",
    "ladder_climb": "the five rungs' OPRO climbs on one axis (view of ladder_robustness)",
    "results_ladder": "the AME `results`-family cascade ablation (CI climbs + framing x "
                      "escaping 2x2); the AME analogue of ladder_robustness, D-106-separate",
    "pareto": "robustness/cost pareto over serialisations (tokens per call vs AUC-ASR)",
    "injection_recall": "per-monitor recall on the injection corpus: what each reviewer "
                        "catches of the same attack set",
    "multiagent_recall": "the fleet arms: recall when the attack is spread across agents "
                         "instead of concentrated in one",
    "pmgrid": "the P×M affordance grid on leak_credentials vs auto mode: leaks/50 and recall "
              "across the technique ladder P0..P5 x the monitor-facts ladder M0..M4",
    "simulation_grid": "auto-mode-eval's capability (simulation) eval: 7 attack briefs x 12 "
                       "monitor arms; the paper's figure 1 maxes over 5 x 5 of it",
    "fairgrid": "the DE-HINTED twin of opus5_grid: attacker x monitor MODEL landing on the "
                "leak_credentials lc3c injection with the mechanism withheld, 3 AME "
                "architectures; source of the appendix A.1 print figure",
    "opus5_grid": "the opus-5 attacker ablation: attacker x monitor MODEL landing on the "
                  "leak_credentials lc3c injection, across 3 AME architectures (first-look)",
    "opus5_grid_per_attempt": "opus5_grid divided by trials that attempted the exfil "
                              "(willingness-controlled view of opus5_grid)",
}


# Figures that are a second VIEW of another figure's data rather than a separate
# measurement. They have a builder and a PNG but no data file and no extractor of their
# own, and that is correct -- inventing an extractor that duplicates the source's work
# would let the two drift. `--extract` re-derives the SOURCE once; `--list` says so
# instead of reporting NO-DATA.
VIEW_OF: dict[str, str] = {"ladder_climb": "ladder_robustness",
                           "opus5_grid_per_attempt": "opus5_grid"}


def data_file_for(name: str):
    """The json a figure actually reads, following the view alias."""
    return figlib.DATADIR / f"{VIEW_OF.get(name, name)}.json"


# Extractors that need a module the plotting venv does not have.
# The capability results are one YAML per cell.
EXTRACT_REQUIRES: dict[str, list[str]] = {"simulation_grid": ["yaml"]}


def _interpreter_for(name: str, override: str | None) -> str:
    """Pick a python that can run this extractor, or fail loudly saying what is needed."""
    needs = EXTRACT_REQUIRES.get(name, [])
    candidates = [override] if override else []
    candidates += [sys.executable, str(figlib.MONOREPO / ".venv/bin/python")]
    for cand in candidates:
        if not cand or not Path(cand).exists():
            continue
        if not needs:
            return cand
        probe = subprocess.run(
            [cand, "-c", "import " + ", ".join(needs)],
            capture_output=True, text=True, check=False)   # returncode IS the answer
        if probe.returncode == 0:
            return cand
    raise figlib.MissingInput(
        f"no python available that can import {needs} for the {name!r} extractor; "
        f"pass --extract-python <path> (tried: {[c for c in candidates if c]})")


def extract(name: str, override: str | None = None, _done: set[str] | None = None) -> None:
    source = VIEW_OF.get(name)
    if source is not None:
        # A view has no data of its own; re-derive what it reads instead of failing.
        if _done is not None and source in _done:
            print(f"[extract] {name}: view of {source}, already re-derived this run")
            return
        print(f"[extract] {name}: view of {source} -- re-deriving that instead")
        extract(source, override, _done)
        if _done is not None:
            _done.add(source)
        return
    script = HERE / "extract" / f"extract_{name}.py"
    if not script.exists():
        raise figlib.MissingInput(f"no extractor for {name!r}: {script}")
    python = _interpreter_for(name, override)
    print(f"[extract] {figlib.rel(script)}  (python: {python})")
    # check=False: the raise below carries the figure name, which CalledProcessError does not.
    r = subprocess.run([python, str(script)], cwd=str(HERE.parents[1]), check=False)
    if r.returncode != 0:
        raise RuntimeError(f"extractor for {name!r} failed (exit {r.returncode})")


def build(name: str) -> Path:
    mod = importlib.import_module(f"builders.{name}")
    return mod.build()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", metavar="NAME", help="build a single figure")
    ap.add_argument("--extract", action="store_true",
                    help="re-derive data/*.json from the raw sources before plotting")
    ap.add_argument("--extract-python", metavar="PATH", default=None,
                    help="interpreter to run the extractors with (default: this one, "
                         "falling back to the research corpus's .venv python where a "
                         "module such as inspect_ai is required)")
    ap.add_argument("--list", action="store_true", help="list figures and their data files")
    args = ap.parse_args()

    if args.list:
        for name, intent in FIGURES.items():
            data = data_file_for(name)
            print(f"{name:26} {'OK ' if data.exists() else 'NO-DATA'}  {intent}")
            via = f"  (view of {VIEW_OF[name]})" if name in VIEW_OF else ""
            print(f"{'':26} data: {figlib.rel(data)}{via}")
            print(f"{'':26} out:  {figlib.rel(figlib.OUTDIR / (name + '.png'))}")
        return 0

    names = [args.only] if args.only else list(FIGURES)
    unknown = [n for n in names if n not in FIGURES]
    if unknown:
        ap.error(f"unknown figure(s) {unknown}; known: {list(FIGURES)}")

    built, failed = [], []
    extracted: set[str] = set()
    for name in names:
        try:
            if args.extract:
                extract(name, args.extract_python, extracted)
                extracted.add(VIEW_OF.get(name, name))
            path = build(name)
            built.append((name, path))
            print(f"[ok]   {name:26} -> {figlib.rel(path)}")
        except Exception as exc:  # noqa: BLE001 -- report, never silently skip
            failed.append((name, exc))
            print(f"[FAIL] {name:26} {type(exc).__name__}: {exc}", file=sys.stderr)
            if not isinstance(exc, figlib.MissingInput):
                traceback.print_exc()

    print(f"\n{len(built)}/{len(names)} figures built into {figlib.rel(figlib.OUTDIR)}")
    for name, exc in failed:
        print(f"  FAILED {name}: {type(exc).__name__}: {str(exc).splitlines()[0]}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
