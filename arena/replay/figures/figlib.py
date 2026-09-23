"""Shared plumbing for the end-to-end figure pipeline.

Every figure in this pipeline reads a COMMITTED JSON under ``replay/figures/data/``.
No figure module may contain a measured number as a literal: if you find yourself
typing a percentage into a builder, it belongs in the JSON with a ``source`` string
instead.

Two hard rules this module enforces:

1. ``load(name)`` raises ``MissingInput`` (naming the exact file) when a data file
   is absent. A loud missing figure is correct; an invented one is not.
2. ``require(record, key, where)`` raises rather than defaulting, so a hole in the
   data can never silently render as 0.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

FIGDIR = Path(__file__).resolve().parent
DATADIR = FIGDIR / "data"
# Overridable for the SAME reason MONOREPO and SOURCE_REPO are: a test must be able to render
# somewhere other than the committed output. Without this the suite wrote into the very directory
# it byte-compares against, so a corrupted data file was red once and green on every run after --
# the oracle laundered exactly the drift it exists to catch.
OUTDIR = Path(os.environ.get("REPLAY_FIGURE_OUT", FIGDIR / "out"))
PAPER_REPO = FIGDIR.parents[1]

# Read-only source tree the EXTRACTORS (never the builders) reach into, for the
# 2026-06-26 pareto aggregate that was never copied into this repo. Override with $FIGURE_SOURCE.
MONOREPO = Path(os.environ.get("FIGURE_SOURCE", "/nonexistent/research-corpus"))

# The read-only tree the injection extractors reach into for the RUN ARTIFACTS: the
# per-arm checkpoints, the census train sets, the variant registry, and the portal
# payload the hyperparameter strings are read out of. Those are search-trace bulk and
# stay out of this repo under M-5 ("evidence travels; its bulk does not") -- the extractors read
# 58 MB from this tree, against the 169 KB of committed data the builders read. Override with $REPLAY_FIGURE_SOURCE.
#
# Every path this points at is recorded, with its sha256 and byte count, in INPUTS.json
# beside this file. That manifest is what makes the reduction AUDITABLE from a checkout
# that does not have the inputs: you cannot re-derive without them, but you can prove
# which bytes the committed JSON was derived from.
SOURCE_REPO = Path(os.environ.get(
    "REPLAY_FIGURE_SOURCE", "/nonexistent/pi-check-recovered-2026-08-14"))

# auto-mode-eval's own results package, which is where the SIMULATION half of the paper's
# figure 1 comes from -- the auto-mode-eval `paper_results`, one YAML per (attack, monitor) cell
# carrying the scored accuracy, the sample count and the .eval log it was read from.
# Override with $AME_RESULTS.
#
# THIS IS THE PINNED SUBMODULE as of 2026-08-30, and it did not used to be. `paper_results`
# now ships inside `auto-mode-eval/` at the blessed pin -- it appeared at `c100040` with five of
# the seven briefs and is complete at `6ae50ae` -- so the extractor reads the same tree the rest
# of the repo studies, and the "results ahead of the pin" caveat this default used to carry no
# longer applies. The commit read is still written into the data file, because a reader must not
# have to infer it.
#
# $AME_RESULTS still overrides, and remains the way to read a pin that predates the tier (or to
# read upstream's default branch when it is ahead). Point it at a DETACHED WORKTREE, not at
# /nonexistent/auto-mode-eval, which is a working checkout other sessions move around:
#     git -C /nonexistent/auto-mode-eval worktree add --detach \
#         /nonexistent/auto-mode-eval-results origin/main
AME_RESULTS = Path(os.environ.get("AME_RESULTS", str(PAPER_REPO / "auto-mode-eval")))


class MissingInput(RuntimeError):
    """A figure's input is not on disk. Never substitute a plausible value."""


def load(name: str) -> dict:
    """Load ``data/<name>.json``, or fail loudly naming the missing file."""
    path = DATADIR / f"{name}.json"
    if not path.exists():
        raise MissingInput(
            f"missing figure input: {path}\n"
            f"  regenerate it with:  python {FIGDIR / 'extract' / ('extract_' + name + '.py')}\n"
            f"  (or: python {FIGDIR / 'make_all.py'} --extract --only <figure>)"
        )
    return json.loads(path.read_text())


def require(rec: dict, key: str, where: str):
    """Fetch ``rec[key]`` or raise — never default a measured quantity to 0/None."""
    if key not in rec or rec[key] is None:
        raise MissingInput(f"{where}: required field {key!r} is absent/null in the data file")
    return rec[key]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def rel(path: Path) -> str:
    """Path relative to the paper repo, or tagged relative to SOURCE_REPO, else absolute.

    SOURCE_REPO is tried FIRST and tagged, matching `_relativise`. The two disagreed before:
    `rel()` tried PAPER_REPO first and returned a bare relative path, so the same file could be
    recorded two different ways depending on which function wrote it.
    """
    path = Path(path).resolve()
    try:
        return "$REPLAY_FIGURE_SOURCE/" + str(path.relative_to(SOURCE_REPO.resolve()))
    except ValueError:
        pass
    try:
        return str(path.relative_to(PAPER_REPO))
    except ValueError:
        return str(path)


def _relativise(obj):
    """Rewrite any absolute path into this repo -- or into SOURCE_REPO -- as a relative one.

    A figure that ships from the paper repo must not record
    /nonexistent/paper-repo/... in its provenance: that path resolves on
    exactly one machine, which defeats the point of writing provenance down. Applied
    centrally here so an extractor cannot forget. Paths into the MONOREPO are left
    absolute on purpose -- they genuinely are outside this repo, and silently making
    them look local would be worse than leaving them obviously foreign.

    SOURCE_REPO is rewritten for a different reason, and is TAGGED rather than stripped.
    Its checkout location is an accident of where the tree was rescued to, so recording it
    raw would pin provenance to one machine; but stripping it bare would be worse. That
    tree has its own ``replay/`` and ``rollout/`` directories, so a bare
    ``replay/runs/informed_jsonl_text/...`` reads as a path in THIS repository, where it
    resolves to nothing -- a provenance string that looks checkable and is not. Writing
    ``$REPLAY_FIGURE_SOURCE/replay/runs/...`` keeps the stable inner name, keeps
    re-derivation byte-identical on any machine, and makes the foreignness unmistakable.
    """
    root = str(PAPER_REPO) + "/"
    source = str(SOURCE_REPO) + "/"
    if isinstance(obj, str):
        if source in obj:
            obj = obj.replace(source, "$REPLAY_FIGURE_SOURCE/")
        return obj.replace(root, "") if root in obj else obj
    if isinstance(obj, dict):
        return {k: _relativise(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_relativise(v) for v in obj]
    return obj


def write_data(name: str, payload: dict) -> Path:
    """Write a committed data file, pretty and stable."""
    DATADIR.mkdir(parents=True, exist_ok=True)
    path = DATADIR / f"{name}.json"
    path.write_text(json.dumps(_relativise(payload), indent=1, ensure_ascii=False) + "\n")
    return path


def save(fig, name: str) -> Path:
    """Save a figure PNG into ``out/`` and return the path."""
    OUTDIR.mkdir(parents=True, exist_ok=True)
    path = OUTDIR / f"{name}.png"
    # No bbox_inches="tight": the builders reserve their own margins via finish(), and a
    # tight recrop would silently undo that reservation.
    fig.savefig(path, dpi=170)
    # Release it. pyplot keeps every figure alive until closed, and nothing here closed one --
    # harmless for a single make_all pass, but the suite now renders each figure three times
    # (byte-identity, sensitivity baseline, sensitivity perturbed) and matplotlib starts warning.
    # Imported lazily so the scoring path never pulls pyplot in.
    import matplotlib.pyplot as _plt
    _plt.close(fig)
    return path


def titles(ax, title: str, subtitle: str | None = None, pad: int = 30):
    """Left-aligned title + deck, with enough headroom that they never collide."""
    import style as _style
    ax.set_title(title, loc="left", pad=pad)
    if subtitle:
        ax.text(0, 1.015, subtitle, transform=ax.transAxes, ha="left", va="bottom",
                fontsize=9.5, color=_style.INK2)


def caption_lines(fig, lines, pad_in: float = 0.10, dy_in: float = 0.155,
                  fontsize: float = 7.4) -> float:
    """Stack provenance/honesty lines at the figure foot, spaced in INCHES.

    Inch spacing (not figure fractions) keeps the caption block the same physical size
    whether the figure is 5 inches tall or 13. Returns the fraction of figure height the
    block consumes, so the caller can reserve it.
    """
    import textwrap

    import style as _style
    width_in, height = fig.get_size_inches()
    # DejaVu Sans at `fontsize` pt averages ~0.52 em per char -> chars that fit the figure.
    ncols = max(60, int((width_in * 72.0 * 0.985) / (fontsize * 0.52)))
    wrapped: list[str] = []
    for line in [l for l in lines if l]:
        wrapped.extend(textwrap.wrap(line, ncols) or [""])
    for i, text in enumerate(reversed(wrapped)):
        fig.text(0.006, (pad_in + i * dy_in) / height, text, ha="left", va="bottom",
                 fontsize=fontsize, color=_style.MUTED)
    return (pad_in + len(wrapped) * dy_in) / height


def finish(fig, lines, left: float = 0.09, right: float = 0.985,
           title_in: float = 0.95, xlabel_in: float = 0.60, **caption_kw) -> None:
    """Draw the caption block, then reserve exact room for it and for the title deck."""
    used = caption_lines(fig, lines, **caption_kw)
    height = fig.get_size_inches()[1]
    fig.subplots_adjust(left=left, right=right,
                        top=1 - title_in / height,
                        bottom=used + xlabel_in / height)


def source_note(data: dict, extra: str = "") -> str:
    """The 'where did this come from' caption line for a figure."""
    bits = []
    if extra:
        bits.append(extra)
    bits.append("data: replay/figures/data/{}.json  (regenerate: make_all.py --extract --only {})".format(data["figure"], data["figure"]))
    return "  ".join(bits)


def bar_value_labels(ax, bars, values, fontsize: float = 12.0, pad: float = 1.8) -> None:
    """Label every bar the SAME way: its value, above it, in ink, on an opaque halo.

    One style for the whole row, decided once. The obvious alternative -- inside the bar when
    it is tall enough, above it when it is not -- gives a five-bar row two label colours and
    two baselines, which reads as two data series. The halo is what makes one style possible:
    a bar that nearly reaches a reference line used to print its label straight across the
    dash, and a surface-coloured `bbox` masks the line behind the text instead.

    White is deliberately NOT used: the gallery's ink-on-mark colour is `style.SURFACE`,
    and a fixed white also silently fails contrast the first time a
    caller picks a light bar colour.

    `pad` is the gap above the bar, in axis units -- layout.
    """
    import style as _style
    halo = {"facecolor": _style.SURFACE, "edgecolor": "none", "pad": 1.2, "alpha": 0.9}
    for bar, value in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, value + pad, pct(value),
                ha="center", va="bottom", fontsize=fontsize, fontweight="bold",
                color=_style.INK, zorder=5, bbox=halo)


def zero_stubs(ax, bars, values, color, lw: float = 3.2, eps: float = 0.4) -> None:
    """Draw a visible mark under any bar whose measured value is (about) zero.

    A measured zero draws no rectangle, so "we measured 0" and "this arm never ran" render
    identically -- which matters most on exactly the figures where the arms have unequal
    denominators. This is that shared stub.
    """
    for bar, value in zip(bars, values):
        if value < eps:
            ax.plot([bar.get_x(), bar.get_x() + bar.get_width()], [0, 0], color=color,
                    lw=lw, solid_capstyle="butt", zorder=3)


def pct(value: float) -> str:
    """Percent label without a spurious trailing .0 (100% not 100.0%, 62.5% not 62%)."""
    return (f"{value:.0f}%") if abs(value - round(value)) < 0.05 else (f"{value:.1f}%")
