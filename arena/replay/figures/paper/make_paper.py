#!/usr/bin/env python3
"""Rebuild every PRINT figure -- the PDFs the LaTeX source includes -- from committed data.

    replay/.venv/bin/python replay/figures/paper/make_paper.py
    replay/.venv/bin/python replay/figures/paper/make_paper.py --list
    replay/.venv/bin/python replay/figures/paper/make_paper.py --only hardening_rollout
    replay/.venv/bin/python replay/figures/paper/make_paper.py --out ~/overleaf-project/figures

Same contract as `make_all.py`, which is the point of it living here:

  * A builder may NOT contain a measured number. Every value is read from the same
    committed `replay/figures/data/<figure>.json` the gallery reads.
  * A missing input FAILS LOUDLY naming the file, never renders a plausible substitute.
  * The PDFs are byte-reproducible (no /CreationDate), and `replay/tests/
    test_paper_figures.py` redraws each one and compares it against the committed bytes.

There is no `--extract` here on purpose. These figures have no data of their own -- every
one reads a gallery figure's JSON -- so re-deriving is `make_all.py --extract --only <source>`
and then rebuilding here. A second extractor computing the same numbers is a second thing
to drift.

INTO OVERLEAF. `--out ~/overleaf-project/figures` writes the PDFs straight into the LaTeX
tree; commit them there in the same change as any caption edit. That copy is deliberately
manual: the Overleaf repo is a different repository with a different review path, and a
build step that silently rewrote it would put un-reviewed numbers in the paper.
"""
from __future__ import annotations

import argparse
import importlib
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))     # replay/figures -- for figlib, style, paper.*

import figlib                                                    # noqa: E402
from paper import printstyle                                     # noqa: E402

# print figure -> (the data files it reads, one-line intent). A figure may read more than
# one: figure 1 averages a re-derived campaign half with a lifted-literal half, and BOTH
# have to be load-bearing, so the suite perturbs each source independently.
PAPER_FIGURES: dict[str, tuple[tuple[str, ...], str]] = {
    "affordance_pm_grid": (
        ("pmgrid",),
        "appendix A.10: the P x M affordance grid as five small multiples -- what technique "
        "knowledge and monitor knowledge each buy, against the matched no-monitor control; "
        "replaces the 6x5 table"),
    "injection_model_grid": (
        ("fairgrid",),
        "appendix A.1: the de-hinted attacker x monitor grid on leak_credentials lc3c, two "
        "arms in one figure -- the deployed monitor on the production text rendering beside the "
        "hardened cascade on the JSON-record rendering, on one colour scale"),
    "hardening_replay": (
        ("results_ladder",),
        "figure 3(a): the encoding x heredoc 2x2 OPRO climbs on the AME results monitor "
        "(text / +heredoc / JSON-L / +heredoc) -- heredoc needs the JSON-L substrate"),
    "hardening_rollout": (
        ("injection_arena_sim",),
        "figure 5(a): per-monitor injection ASR pooled over the arena and simulation evaluation "
        "families, with Wilson intervals -- the monitor-injection row of figures 1 and 3"),
}


def data_files_for(name: str) -> list[Path]:
    return [figlib.DATADIR / f"{s}.json" for s in PAPER_FIGURES[name][0]]


def data_file_for(name: str) -> Path:
    """The first source. Use data_files_for() unless you specifically want the primary."""
    return data_files_for(name)[0]


def build(name: str) -> Path:
    return importlib.import_module(f"paper.builders.{name}").build()


def summary(name: str) -> str:
    mod = importlib.import_module(f"paper.builders.{name}")
    return mod.summary() if hasattr(mod, "summary") else ""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", metavar="NAME", help="build a single figure")
    ap.add_argument("--list", action="store_true", help="list figures and their data files")
    ap.add_argument("--out", metavar="DIR", default=None,
                    help="write the PDFs here instead of paper/out (e.g. the Overleaf tree)")
    args = ap.parse_args()

    if args.list:
        for name, (sources, intent) in PAPER_FIGURES.items():
            files = data_files_for(name)
            ok = all(f.exists() for f in files)
            print(f"{name:24} {'OK ' if ok else 'NO-DATA'}  {intent}")
            for source, data in zip(sources, files):
                mark = "" if data.exists() else "   <-- MISSING"
                print(f"{'':24} data: {figlib.rel(data)}  (from the {source} figure){mark}")
            print(f"{'':24} out:  {figlib.rel(printstyle.OUTDIR / (name + '.pdf'))}")
        return 0

    if args.out:
        printstyle.OUTDIR = Path(args.out).expanduser().resolve()

    names = [args.only] if args.only else list(PAPER_FIGURES)
    unknown = [n for n in names if n not in PAPER_FIGURES]
    if unknown:
        ap.error(f"unknown figure(s) {unknown}; known: {list(PAPER_FIGURES)}")


    built, failed = [], []
    for name in names:
        try:
            path = build(name)
            built.append(name)
            print(f"[ok]   {name:24} -> {figlib.rel(path)}")
            note = summary(name)
            if note:
                print(f"{'':7}{'':24}    {note}")
        except Exception as exc:  # noqa: BLE001 -- report, never silently skip
            failed.append((name, exc))
            print(f"[FAIL] {name:24} {type(exc).__name__}: {exc}", file=sys.stderr)
            if not isinstance(exc, figlib.MissingInput):
                traceback.print_exc()

    print(f"\n{len(built)}/{len(names)} print figures built into "
          f"{figlib.rel(printstyle.OUTDIR)}")
    for name, exc in failed:
        print(f"  FAILED {name}: {type(exc).__name__}: {str(exc).splitlines()[0]}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
