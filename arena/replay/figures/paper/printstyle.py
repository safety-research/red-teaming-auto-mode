"""Shared plumbing for the PRINT figures — the PDFs the LaTeX source includes.

Separate from `figures/style.py` on purpose. That module dresses the GALLERY: ~11in
screen PNGs at dpi 170, carrying their own titles and a stacked provenance caption,
meant to be opened on their own and understood without the paper around them. These
are the opposite product — 3.15in wide, 8pt type, no title, no caption block, because
LaTeX draws the caption and the surrounding text supplies the context. Rendering one
from the other means either shrinking a gallery figure until its 12pt labels are
illegible, or stripping the parts that make it self-describing.

What IS shared, and must stay shared: the data (`figlib.load`, the same committed
`data/*.json` the gallery reads). The COLOURS are no longer shared. As of 2026-08-30 all six print
figures are on the **Redline** system (`REDLINE` below) and the gallery is not, because the
paper was printing three families of red for one role -- a bright categorical #E34948 in
the hardening panels beside a stock-`Reds` sequential ramp topping out at #E83429, ΔE76
16.8 apart, which reads as one encoding used inconsistently, plus the deep crimson of the
two appendix grids. The gallery keeps `style.py`: it is 19 committed PNGs behind a
byte-identity oracle and a portal, so moving it is a separate decision and not this one.

The tier's rules, so a seventh figure does not have to re-derive them: colour comes from
`REDLINE` and nothing else (`tests/test_paper_figures.py::test_print_palette_is_the_redline_
token_table` inlines the table so it is checkable on a clone, with the kit comparison as an
extra where the untracked kit exists); a magnitude is the `SEVERITY_RAMP`, whose white-text
crossover is DERIVED by `severity_white_above()` rather than picked; two categories that
mean "the attack landed" and "the defence held" are `ATTACK` and `DEFENCE`; the spine is
`AXIS` and the gridline `GRID`, once, for every figure.

The NEUTRALS are deliberately not the gallery's, and the check exempts them by name.
`style.INK` is #0b0b0b on a #fcfcfb surface, tuned for a backlit screen; on paper that
pairing is harsher than it needs to be and the gallery's #e1e0d9 grid all but vanishes
at 3.15in. These are the print set: a softer ink, a darker muted, a slightly cooler grid.

PRINT SIZING. Every figure here is generated at the physical size it occupies in the
paper and included at `width=\\linewidth`, so nothing is scaled and the type renders at
the pt size set here. `WIDTH_IN`/`HEIGHT_IN` are 0.48\\linewidth of ICLR's text block,
which is 5.5in (`iclr2027_conference.sty:49`) and NOT the 6.5in this module used to
claim; a figure that wants the full width sets its own. The wrong text block made the two
`fig:format-hardening` canvases 3.15in wide against a 2.64in slot, so pdfTeX scaled them
DOWN by 0.838 on the page and the authored 8pt type printed at 6.7pt -- authored pt was
not printed pt, which is the one thing this tier exists to guarantee. See `STROKE`.

DETERMINISM. `save()` suppresses the PDF's /CreationDate, without which every rebuild
differs in bytes and the byte-identity test could not exist. Fonts are embedded as
TrueType (`pdf.fonttype: 42`) rather than converted to paths, so the text stays
selectable and greppable in the built PDF -- which is how the numbers in the retired
`asr_max_by_monitor.pdf` were recoverable at all.
"""
from __future__ import annotations

import math
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Overridable for the same reason REPLAY_FIGURE_OUT is: the suite must be able to render
# somewhere other than the committed output, or the oracle launders the drift it exists
# to catch. `make_paper.py --out` sets it too, which is how the Overleaf tree is fed.
OUTDIR = Path(os.environ.get("PAPER_FIGURE_OUT", HERE / "out"))

# NEUTRALS. Print-specific, and as of 2026-08-30 they are Redline's: `INK` and `MUTED` already
# WERE `--ink` and `--chart-label` by coincidence of tuning, and `GRID` moved the last 3.5 ΔE onto
# `--chart-grid`. `AXIS` is new and is the tier's one spine colour -- the two grid figures had
# arrived at two different spine greys (#C3CAC6 and #9AA39E) and the four older ones at a third
# (#5E6662), which is three weights of the same line on one page.
INK, MUTED, GRID = "#1D2422", "#5E6662", "#E2E6E4"
AXIS = "#9AA39E"

# REDLINE, for a SEQUENTIAL scale. The four CAT slots above are a series palette and a
# heatmap needs a ramp, so `injection_model_grid` reads this instead. Every value is
# transcribed from the Redline kit's `tokens/colors.css` and carries the custom property it
# came from -- the same by-value copy the CAT slots are, and checked the same way, by
# `test_redline_ramp_tracks_the_kit` against `figures/redline/tokens.py` (the kit's
# matplotlib port) wherever that port is on disk. Two of the neutrals above already ARE
# these tokens by coincidence of tuning -- INK is `--ink` and MUTED is `--chart-label` --
# which is why only the hues and two greys are new here.
#
# Adopting Redline for the whole gallery is a separate and much larger decision (it rewrites
# every committed PNG and its byte-identity oracle); this is one figure's colour scale.
REDLINE = {
    "surface_card": "#FFFFFF",      # --surface-card
    "surface_tint": "#F1F3F2",      # --neutral-100 / --surface-tint
    "border_strong": "#C3CAC6",     # --neutral-300 / --border-strong
    "chart_axis": "#9AA39E",        # --neutral-400 / --chart-axis
    "chart_label": "#5E6662",       # --neutral-600 / --chart-label  (== MUTED)
    "ink": "#1D2422",               # --ink / --text-body            (== INK)
    "amber_100": "#F5EBD6",         # --amber-100
    "amber_300": "#DCC286",         # --amber-300
    "crimson_500": "#A3323F",       # --crimson-500 / --role-attacker
    "crimson_700": "#7C232E",       # --crimson-700 / severity "critical"
    "cobalt_700": "#1F4288",        # --cobalt-700  / --role-blue-team
    "teal_500": "#0F766E",          # --teal-500    / --role-monitor ("the defence", "ours")
    "crimson_100": "#F6E3E5",       # --crimson-100 / tint for "the attack landed"
    "amber_500": "#B58A2E",         # --amber-500   / --series-4 / severity "warning"
    "chart_grid": "#E2E6E4",        # --neutral-200 / --chart-grid / --border-default
}

# The two ACTOR colours the print tier encodes with, by the kit's own semantics rather than by
# series index: a rendering the attacker beats is crimson (`--role-attacker`), a hardened one is
# teal (`--role-monitor`, whose alias in the kit is "the defence"). Used by both hardening panels
# and by nothing else, so the two figures of `fig:format-hardening` agree by construction.
ATTACK, DEFENCE = REDLINE["crimson_500"], REDLINE["teal_500"]

# The severity ramp itself: (position, token). An ADDITION in the sense the kit's own port
# uses the word -- colors.css ships discrete tones and a heatmap needs the values between
# them. Low end is the surface tint rather than white, so a 0% cell still reads as a cell
# against the page; then amber (the kit's "caveat") and crimson (its "attack"), whose
# luminance falls monotonically, so the grid survives a greyscale print.
SEVERITY_RAMP = ((0.00, REDLINE["surface_tint"]), (0.10, REDLINE["amber_100"]),
                 (0.34, REDLINE["amber_300"]), (0.58, REDLINE["amber_500"]),
                 (0.82, REDLINE["crimson_500"]), (1.00, REDLINE["crimson_700"]))

WIDTH_IN, HEIGHT_IN = 2.64, 1.885714   # 0.48\linewidth of ICLR's 5.5in text block, at 1:1
# The canvas above USED to be 3.15 x 2.25in ("0.48 of a 6.5in text block"): 19% oversize, so
# pdfTeX scaled it by this factor on the page and every authored point value -- type, stroke,
# pad, marker -- printed at 0.838 of itself. Correcting the canvas is meant to change the TYPE
# only, so the weights authored for the old canvas are multiplied by `STROKE` and their PRINTED
# weight is unchanged. The aspect ratio is preserved, so the printed geometry -- and with it the
# (a)/(b) alignment -- is identical to the shipped figure.
STROKE = 2.64 / 3.15
# Type is NOT scaled by STROKE: at 1:1 that would just print the old 6.03/6.70/7.12pt again. The
# ladder is compressed into the paper's 6.3-7.2pt printed band instead, base at 7.0. A uniform
# rescale cannot do it -- a base in [6.8, 7.2] puts the axis labels at 8.5 * base/8 = 7.2-7.6pt,
# over the ceiling -- so the three sizes are set here, in PRINTED pt, once for the tier.
# FS_LEGEND is the one size the canvas CAPS, so it sits at the band's floor rather than in it:
# hardening_replay's legend is centred on the AXES, which sit 17.6pt right of the canvas centre,
# so its right edge runs out of MediaBox and pdfTeX clips it (the defect D3 describes on panel
# (b)'s `100` tick). Measured legend right margin: 5.6pt printed as shipped at 6.03, 2.5pt at
# 6.3, 1.3pt at 6.4, clipped above ~6.5.
FS_BASE, FS_AXIS, FS_LEGEND = 7.0, 7.2, 6.3
# Both panels of the format-hardening figure are pinned to the same vertical band so they
# align on the page: same plot-area height, same baseline. Only the left edge differs,
# since (b) carries row labels where (a) carries a y axis. Set explicitly rather than by
# tight_layout, which fits each panel to its own content and puts the two baselines at
# different heights.
BOTTOM, TOP = 0.325, 0.965

RCPARAMS = {
    "font.family": "DejaVu Sans", "font.size": FS_BASE,
    "axes.edgecolor": AXIS, "axes.labelcolor": MUTED,
    "xtick.color": MUTED, "ytick.color": MUTED,
    # text.color is set here and not per figure: `affordance_pm_grid` omitted it from its own
    # `apply(extra)` and its three legend labels came out matplotlib-default BLACK -- the only
    # #000000 in the tier, and invisible in review because black-on-white looks intentional.
    "text.color": INK,
    "axes.titlelocation": "left",   # the kit sets headings left; matplotlib centres them
    "pdf.fonttype": 42, "svg.fonttype": "none",
}


def _relative_luminance(hex_colour: str) -> float:
    """WCAG relative luminance of an #RRGGBB string."""
    rgb = [int(hex_colour[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    lin = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def _contrast(a: str, b: str) -> float:
    la, lb = _relative_luminance(a), _relative_luminance(b)
    lo, hi = sorted((la, lb))
    return (hi + 0.05) / (lo + 0.05)


def severity_white_above(ramp=SEVERITY_RAMP) -> int:
    """The percentage above which white type beats ink ON THIS RAMP, by WCAG contrast.

    DERIVED, not chosen, and it lives here rather than in a data file because it is a property
    of the RAMP: the gallery's ramp and this one cross over at different values, so one field in
    `data/*.json` cannot serve both. The figures that hand-picked 55 put white 6.5pt digits on
    mid-amber at 3.2:1 where ink on the same tile was 5.0:1 -- the least legible number on the
    page was the one the ramp had already coloured to draw the eye.
    """
    from matplotlib.colors import LinearSegmentedColormap, to_hex
    cmap = LinearSegmentedColormap.from_list("severity", ramp)
    for pct in range(0, 101):
        tile = to_hex(cmap(pct / 100.0)).upper()
        if _contrast(REDLINE["surface_card"], tile) > _contrast(INK, tile):
            return pct
    return 100


SEVERITY_WHITE_ABOVE = severity_white_above()

def apply(extra: dict | None = None) -> None:
    """Reset to matplotlib's defaults, THEN apply the print set.

    The reset is load-bearing, not tidiness. `style.apply()` mutates the global rcParams
    for the gallery -- 11pt type, a #fcfcfb figure face, spines off, lines at 2.0 -- and
    whatever ran first in the process wins. RCPARAMS below names only what print
    OVERRIDES, so without the reset a print figure rendered after a gallery figure comes
    out with the gallery's facecolour and line weights, and one rendered alone does not.
    That is exactly what happened: both PDFs redrew byte-identically when
    `test_paper_figures.py` ran on its own and differed under the full `./check replay`,
    where `test_figures.py` had already applied the gallery style.
    `test_print_style_is_isolated_from_the_gallery` is the regression.

    `extra` is for a figure that sits at a different size on the page and therefore wants
    a different type scale -- figure 1 is full text-block width at 9pt where the hardening
    panels are half-width at 8pt. It is applied last, over RCPARAMS.
    """
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcdefaults()            # `backend` is style-blacklisted, so Agg survives this
    plt.rcParams.update(RCPARAMS)
    if extra:
        plt.rcParams.update(extra)


def frame(ax, xlabel: str, ylabel: str) -> None:
    """The house frame for a print panel: labelled, de-boxed, hairline spines."""
    # axis titles in --chart-label, not ink: the kit's figure anatomy sets both axis labels to
    # `var(--chart-label)` and reserves ink for headings and values.
    ax.set_xlabel(xlabel, fontsize=FS_AXIS, color=MUTED, labelpad=2 * STROKE)
    ax.set_ylabel(ylabel, fontsize=FS_AXIS, color=MUTED, labelpad=2 * STROKE)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("bottom", "left"):
        ax.spines[side].set_linewidth(0.6 * STROKE)
        ax.spines[side].set_color(AXIS)
    # length=0: the kit's port removes protruding tick marks ("labels only, hairline structure").
    ax.tick_params(length=0, width=0.6 * STROKE, labelsize=FS_BASE, pad=2 * STROKE)


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson interval as percentage points either side of k/n.

    Wilson rather than normal-approximation: two of the three rows this draws are at or
    near a boundary (0/218), where the normal interval is [0, 0] -- an error bar
    asserting certainty from the one result that has the least of it.
    """
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return 100 * max(0.0, p - (centre - half)), 100 * max(0.0, (centre + half) - p)


def save(fig, name: str) -> Path:
    """Write ``<OUTDIR>/<name>.pdf``, byte-reproducibly, and close the figure."""
    OUTDIR.mkdir(parents=True, exist_ok=True)
    path = OUTDIR / f"{name}.pdf"
    # CreationDate is the ONLY nondeterminism in matplotlib's PDF output; suppressing it
    # is what lets the suite byte-compare a rebuild against the committed file.
    fig.savefig(path, metadata={"CreationDate": None})
    import matplotlib.pyplot as plt
    plt.close(fig)
    return path
