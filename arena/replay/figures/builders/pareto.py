"""Figure `pareto` -- robustness/cost pareto over serialisations.

Port of `replay/scripts/informed_jsonl_text/make_pareto{,_clean,_decluttered}.py` onto the
committed JSON: same dominance rule, same cache-aware x-axis, same family colouring and
callout set, but the numbers now arrive from ``data/pareto.json`` instead of from a
`--base` directory of run artifacts, and the shared paper palette replaces the ad-hoc one.

Two panels: AUC-ASR (the primary safety axis) and final ASR (the ceiling-only companion),
exactly the pair `make_pareto.py:_METRICS` emits.
"""
from __future__ import annotations

import figlib
import matplotlib.pyplot as plt
import style
from matplotlib.lines import Line2D

NAME = "pareto"

FAMILY_COLOUR = {"text": style.CAT["red"], "jsonl": style.CAT["yellow"], "xml": style.CAT["blue"]}

# Label placement ported verbatim from make_pareto_clean.py:LABELS -- (dx, dy, ha).
# Placement only; it carries no measured value.
LABELS = {
    "text": (6, 6, "left"),
    "text_full": (6, -2, "left"),
    "jsonl": (7, 9, "left"),
    "jsonl_escape": (-8, -6, "right"),
    "jsonl_heavy": (8, 6, "left"),
    "text_hd_full": (8, 8, "left"),
    "xml_heavy": (8, -2, "left"),
    "jsonl_heredoc_angle": (-10, 12, "right"),
    "jsonl_heredoc_escape": (6, -12, "left"),
    "xml_id_escape": (6, 8, "left"),
    "jsonl_heredoc": (8, 6, "left"),
    "xml_hd_heavy": (-8, 0, "right"),
}

PANELS = [
    ("auc_asr_mean", "auc_asr_std",
     "attacker-effort-weighted ASR   (AUC, %)",
     "Safety = AUC-ASR: folds the ceiling AND the speed of reaching it into one axis."),
    ("final_asr_mean", "final_asr_std",
     "final attack success rate   (%)",
     "Ceiling only -- it ties every cell that eventually reaches 100%."),
]


def pareto_front(points: dict[str, tuple[float, float]]) -> set[str]:
    """make_pareto.py:_pareto_front -- minimise BOTH cost and ASR."""
    front = set()
    for a, (xa, ya) in points.items():
        if not any(b != a and xb <= xa and yb <= ya and (xb < xa or yb < ya)
                   for b, (xb, yb) in points.items()):
            front.add(a)
    return front


def _panel(ax, pts, mean_key, std_key, ylabel, subtitle, base_tok):
    xy = {p["name"]: (p["cost_tokens"], 100.0 * p[mean_key]) for p in pts}
    front = pareto_front(xy)
    frontier = sorted((xy[n] for n in front), key=lambda q: q[0])
    if len(frontier) >= 2:
        ax.plot([q[0] for q in frontier], [q[1] for q in frontier], ls="--", lw=1.6,
                color=style.BASELINE, zorder=1, label="pareto frontier")

    for p in pts:
        name = p["name"]
        x, y = xy[name]
        err = 100.0 * p[std_key]
        colour = FAMILY_COLOUR.get(p["family"], style.MUTED)
        on = name in front
        ax.errorbar(x, y, yerr=err, fmt="o", ms=11 if on else 7.5, color=colour,
                    ecolor=colour, elinewidth=1.2, capsize=3, alpha=0.97,
                    mec=style.INK if on else style.SURFACE, mew=1.5 if on else 1.0,
                    zorder=4 if on else 3)
        if on or name in LABELS:
            dx, dy, ha = LABELS.get(name, (8, 5, "left"))
            ax.annotate(p["short_label"], (x, y), textcoords="offset points", xytext=(dx, dy),
                        ha=ha, fontsize=8.4, fontweight="bold" if on else "normal",
                        color=style.INK if on else style.INK2)

    ax.set_xlabel("serialisation cost   (uncached body tokens per classifier call, cache-aware)")
    ax.set_ylabel(ylabel)
    ax.set_ylim(-5, 108)
    ax.set_yticks([0, 25, 50, 75, 100])
    style.hgrid(ax)
    ax.grid(axis="x", color=style.GRID, linewidth=0.8)
    ax.text(0, 1.115, subtitle, transform=ax.transAxes, ha="left", va="bottom",
            fontsize=9.2, color=style.INK2)

    # secondary x: cost relative to the cheapest serialisation
    top = ax.secondary_xaxis("top", functions=(lambda v: v / base_tok, lambda v: v * base_tok))
    top.set_xlabel("cost relative to the cheapest serialisation (x text)",
                   fontsize=8.2, color=style.MUTED, labelpad=2)
    top.tick_params(labelsize=8, colors=style.MUTED)
    return front


def build():
    data = figlib.load(NAME)
    style.apply()

    pts = figlib.require(data, "points", NAME)
    if not pts:
        raise figlib.MissingInput(f"{NAME}: no pareto cell in the data file")
    base_tok = data["provenance"]["cost_x_denominator_tokens"]

    fig, axes = plt.subplots(1, 2, figsize=(15.6, 6.4))
    fronts = []
    for ax, (mk, sk, ylab, sub) in zip(axes, PANELS):
        fronts.append(_panel(ax, pts, mk, sk, ylab, sub, base_tok))

    handles = [Line2D([], [], marker="o", ls="none", color=c, label=f)
               for f, c in FAMILY_COLOUR.items()]
    handles += [Line2D([], [], ls="--", color=style.BASELINE, label="pareto frontier"),
                Line2D([], [], marker="o", ls="none", mfc=style.MUTED, mec=style.INK, mew=1.5,
                       color=style.MUTED, label="on the frontier")]
    axes[0].legend(handles=handles, loc="lower left", fontsize=9, ncols=2)

    fig.suptitle("Robustness costs tokens -- and only two serialisations buy much of it",
                 fontsize=14.5, fontweight="bold", x=0.008, ha="left", y=0.975)

    auc_front = sorted(fronts[0], key=lambda n: next(p["cost_tokens"] for p in pts if p["name"] == n))
    prov = data["provenance"]
    figlib.finish(fig, [
        prov["one_line"],
        "Bottom-left is best (cheap AND robust). Error bars = 1 SD over {} runs/cell. "
        "AUC frontier: {}.".format("/".join(str(n) for n in sorted({p["n_runs"] for p in pts})),
                               ", ".join(auc_front)),
        data["gaps"][0] + "  " + data["gaps"][2],
        figlib.source_note(data, "Ported from " + ", ".join(data["ported_from"]) + "."),
    ], left=0.065, right=0.99, title_in=1.45, xlabel_in=0.72)
    fig.subplots_adjust(wspace=0.19)
    return figlib.save(fig, NAME)
