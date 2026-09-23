"""The PRINT tier's regression oracle -- the PDFs `sections/*.tex` actually includes.

`test_figures.py` gates the gallery PNGs. This gates the paper's own output, on the same
three properties and for the same reasons, plus three the print tier needs specifically:

4. **Every colour is a Redline token.** The tier is on the kit's palette but the kit itself
   is gitignored and does not ship, so the expected token table is INLINED here -- that is
   the oracle a clone gets. The comparison against the kit's own module is an additional
   check that runs only where that untracked module is on disk.

5. **The severity ramp is monotone.** Its stated property is that luminance falls, so the
   grid survives a greyscale print; a stop inserted out of order breaks that silently in a
   figure where colour IS the value.

6. **Panel (b)'s pool matches its source.** Every cell's carried `asr` must equal its own
   leaks/n and the pooled bar must equal the summed counts, or the figure and the table a reader can
   re-derive by hand say different things.

The AST helpers are IMPORTED from `test_figures` rather than copied: they encode a
subtlety that was got wrong once (exempting a whole subtree exempts `[100.0, 96.5, 85.5]`
too), and a second copy is a second thing to get wrong again.
"""
from __future__ import annotations

import ast
import hashlib
import importlib
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

FIGURES = Path(__file__).resolve().parents[1] / "figures"
sys.path.insert(0, str(FIGURES))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import figlib                                                        # noqa: E402
import style                                                         # noqa: E402  (the GALLERY
#   style, imported only by test_print_style_is_isolated_from_the_gallery, which applies it on
#   purpose to prove a print figure renders the same after the gallery has mutated rcParams)
from paper import printstyle                                         # noqa: E402
from paper.make_paper import PAPER_FIGURES, data_files_for           # noqa: E402
from test_figures import EXEMPT_MARKER, _layout_literals, _measured_floats  # noqa: E402

ALL_PAPER_FIGURES = sorted(PAPER_FIGURES)
OUT = FIGURES / "paper" / "out"


def _sha(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@pytest.mark.parametrize("name", ALL_PAPER_FIGURES)
def test_paper_figure_redraws_byte_identical(name, tmp_path, monkeypatch):
    committed = OUT / f"{name}.pdf"
    assert committed.exists(), f"no committed print figure to compare against: {committed}"

    monkeypatch.setattr(printstyle, "OUTDIR", tmp_path)
    redrawn = importlib.import_module(f"paper.builders.{name}").build()

    assert _sha(redrawn) == _sha(committed), (
        f"{name}.pdf does not reproduce from "
        f"{[f.name for f in data_files_for(name)]}.\n"
        f"  committed {committed.stat().st_size} B, redrawn {redrawn.stat().st_size} B\n"
        f"  Either the data changed without the figure being rebuilt, or the builder did. "
        f"Rebuild with: replay/figures/paper/make_paper.py --only {name}\n"
        f"  Then copy it into the Overleaf tree (--out) in the same change."
    )


@pytest.mark.parametrize("name", ALL_PAPER_FIGURES)
def test_paper_builder_contains_no_measured_value(name):
    """A number typed into a print builder is a number that can drift from the data.

    This is the check panel (b) was ported to satisfy: it used to carry `92, 219` and
    `68, 215` as literals, which redrew its own PDF perfectly forever and would have gone
    on doing so after the grid was re-extracted.
    """
    path = FIGURES / "paper" / "builders" / f"{name}.py"
    src = path.read_text()
    lines = src.splitlines()
    tree = ast.parse(src)
    exempt = _layout_literals(tree)

    measured: set[float] = set()
    for src in data_files_for(name):
        _measured_floats(json.loads(src.read_text()), measured)
    assert measured, (
        f"{[f.name for f in data_files_for(name)]} hold no non-integral float, so this "
        f"check has no power over {name} and must not be reported as a pass."
    )
    baked = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant)
                and isinstance(node.value, (int, float))
                and not isinstance(node.value, bool)):
            continue
        if id(node) in exempt or float(node.value) not in measured:
            continue
        if EXEMPT_MARKER in lines[node.lineno - 1]:
            continue
        baked.append((node.lineno, node.value, lines[node.lineno - 1].strip()))

    assert not baked, (
        f"paper/builders/{name}.py uses literals that also appear as measured values in "
        f"{[f.name for f in data_files_for(name)]}:\n"
        + "\n".join(f"    line {ln}: {val!r} in  {text}" for ln, val, text in baked)
        + f"\n  Read it from the data file. If it genuinely is not a measurement, say so "
          f"inline with '{EXEMPT_MARKER}'."
    )


def _perturb(obj, factor: float = 1.37):
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, (int, float)):
        return obj * factor
    if isinstance(obj, dict):
        return {k: _perturb(v, factor) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_perturb(v, factor) for v in obj]
    return obj


@pytest.mark.parametrize(
    "name,source",
    [(n, s) for n in ALL_PAPER_FIGURES for s in PAPER_FIGURES[n][0]])
def test_paper_figure_is_a_function_of_each_of_its_data_files(name, source, tmp_path,
                                                              monkeypatch):
    """Change ONE source, and the PDF must change. Parametrised per source, not per figure.

    Figure 1 averages a re-derived campaign half with a lifted-literal half. Perturbing
    only the primary would leave the other half free to be hardcoded -- which is exactly
    the state the Overleaf script was in for both halves. Each source has to be load-bearing
    on its own, so each gets its own case and its own name in the report.
    """
    monkeypatch.setattr(printstyle, "OUTDIR", tmp_path)
    baseline = _sha(importlib.import_module(f"paper.builders.{name}").build())

    perturbed = tmp_path / "data"
    perturbed.mkdir(exist_ok=True)
    for src in figlib.DATADIR.glob("*"):          # the untouched sources must still resolve
        if src.is_file():
            (perturbed / src.name).write_bytes(src.read_bytes())
    target = figlib.DATADIR / f"{source}.json"
    (perturbed / target.name).write_text(
        json.dumps(_perturb(json.loads(target.read_text())), ensure_ascii=False))
    monkeypatch.setattr(figlib, "DATADIR", perturbed)
    after = _sha(importlib.import_module(f"paper.builders.{name}").build())

    assert after != baseline, (
        f"{name}.pdf is byte-identical after every number in {target.name} was scaled by "
        f"1.37. That half of the figure is not being read from its data file."
    )


def test_rollout_pool_is_internally_consistent_and_uses_the_current_arm():
    """Panel (a)'s bars, the rates in its data file, and its denominators all agree.

    This replaced a json-vs-csv cross-check when the panel's source moved off the
    cross-environment campaign (2026-09-10). `injection_arena_sim.json` has one serialisation, so the
    invariant worth holding is different: every cell's carried `asr` must equal its own
    leaks/n, the pooled bar must equal the summed counts rather than a mean of the two
    rates, and every row must pool the SAME denominator -- bars over different n are not
    comparable and their Wilson intervals are not either.

    It also pins the arm identity. The shipped figure drew 75.2%, which is `auto mode (old)`
    -- a different arm that sits four characters away in the same frame -- under the label
    "auto mode". Both arms are still in the data file, so the swap is one typo away.
    """
    from paper.builders.hardening_rollout import FAMILIES, ROWS, SOURCE, pooled

    d = figlib.load(SOURCE)
    arms = d["arms"]

    for arm, fams in arms.items():
        for fam, cell in fams.items():
            assert cell["asr"] == pytest.approx(cell["leaks"] / cell["n"], abs=5e-7), (
                f"{arm}/{fam}: carried asr {cell['asr']} != leaks/n "
                f"{cell['leaks']}/{cell['n']}; the export is inconsistent with itself")

    rows = pooled(d)
    assert len({n for _, _, n, _ in rows}) == 1, (
        f"rows pool different denominators: { {r[0]: r[2] for r in rows} }")

    for label, leaks, n, _ in rows:
        want_k = sum(arms[label][f]["leaks"] for f in FAMILIES)
        want_n = sum(arms[label][f]["n"] for f in FAMILIES)
        assert (leaks, n) == (want_k, want_n), (
            f"{label}: builder pooled {leaks}/{n}, data file sums to {want_k}/{want_n}")
        macro = 100 * sum(arms[label][f]["asr"] for f in FAMILIES) / len(FAMILIES)
        micro = 100 * leaks / n
        if label == "auto mode":
            assert abs(micro - macro) > 1.0, (
                "auto mode's micro and macro pools have converged, so this test can no "
                "longer tell which one the builder used; pick another sentinel row")
            assert micro == pytest.approx(78.4, abs=0.05), (
                f"auto mode pooled {micro:.1f}%, not 78.4%. 75.2% means the builder picked up "
                f"'auto mode (old)'; {macro:.1f}% means it macro-pooled the two families, which "
                f"leaves the Wilson intervals without a denominator.")

    assert "auto mode (old)" in arms and arms["auto mode (old)"] != arms["auto mode"], (
        "the data file no longer distinguishes auto mode from auto mode (old); the arm-identity "
        "assertion above has nothing to protect")


def test_every_paper_figure_reads_data_files_that_exist():
    for name in ALL_PAPER_FIGURES:
        for src in data_files_for(name):
            assert src.exists(), (
                f"{name} declares {src.name} in make_paper.PAPER_FIGURES, not on disk")


def test_no_stale_print_output_left_behind():
    stray = {p.stem for p in OUT.glob("*.pdf")} - set(ALL_PAPER_FIGURES)
    assert not stray, f"orphan print figures in replay/figures/paper/out: {sorted(stray)}"


@pytest.mark.parametrize("name", ALL_PAPER_FIGURES)
def test_print_style_is_isolated_from_the_gallery(name, tmp_path, monkeypatch):
    """A print figure renders the same whether or not a gallery figure ran first.

    rcParams are process-global and `style.apply()` sets ~20 of them for an 11in screen
    canvas. `printstyle.RCPARAMS` names only what print OVERRIDES, so the two orderings
    gave two different PDFs until `printstyle.apply()` started with `rcdefaults()`: both
    figures redrew byte-identically when this file ran alone and failed under the full
    `./check replay`, where `test_figures.py` had already applied the gallery style.

    Ordinary test collection does not reproduce that reliably -- it depends which file
    pytest reached first -- so this forces the hostile order explicitly.
    """
    monkeypatch.setattr(printstyle, "OUTDIR", tmp_path)
    style.apply()                                   # the gallery, first
    after_gallery = _sha(importlib.import_module(f"paper.builders.{name}").build())

    assert after_gallery == _sha(OUT / f"{name}.pdf"), (
        f"{name}.pdf differs when a gallery figure rendered first in the same process. "
        f"printstyle.apply() is not resetting rcParams, so the PDF the paper gets depends "
        f"on what else ran."
    )


def test_print_pdfs_carry_no_creation_date():
    """No /CreationDate, or the byte-identity test above could not exist."""
    for name in ALL_PAPER_FIGURES:
        blob = (OUT / f"{name}.pdf").read_bytes()
        assert not re.search(rb"/CreationDate", blob), (
            f"{name}.pdf embeds a /CreationDate, so every rebuild differs in bytes. "
            f"printstyle.save() suppresses it -- this file was not written by it.")
