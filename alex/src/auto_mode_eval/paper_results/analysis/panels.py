"""Figure components shared by more than one figure: the monitor key, and the group split.

Figure 1 is the paper's first, and the reader has met none of the monitors — so it carries a key
naming each and the one way it differs from the monitor it extends. Two drawings of that figure
want the same key, which is why it lives here rather than being pasted into each notebook.
"""

from __future__ import annotations

import re
from textwrap import fill
from typing import NamedTuple

import matplotlib.transforms as mtransforms
from matplotlib.axes import Axes
from matplotlib.patches import Rectangle

from auto_mode_eval.paper_results.analysis.style import (
    ATTACK_CLASS_COLOURS,
    GRID,
    INK,
    MUTED,
    SIZE,
    SURFACE,
)
from auto_mode_eval.paper_results.analysis.tables import ATTACK_CLASSES

# A hue per class is only meaningful while the two agree on what the classes are; a class added to
# one and not the other would otherwise draw in whatever colour `dict.get` last returned.
_uncoloured = set(ATTACK_CLASSES) - set(ATTACK_CLASS_COLOURS)
if _uncoloured:
    raise ValueError(f"attack classes with no colour in `style`: {sorted(_uncoloured)}")


class Entry(NamedTuple):
    """One line of the key: a monitor, the model reviewing for it, and what sets it apart."""

    monitor: str
    model: str
    gloss: str

    @property
    def caption(self) -> str:
        """The model leads, since which model reviews is half of what a row costs and catches."""
        return f"{self.model} — {self.gloss}"


class Group(NamedTuple):
    """A headed block of the key, matching a group of bars on the plot beside it."""

    heading: str
    entries: tuple[Entry, ...]


# The production pair needs no explaining beyond whose product it is; each experimental variant is
# glossed by its differences from the monitor it extends. `*word*` sets that word in italic.
MONITOR_KEY: tuple[Group, ...] = (
    Group("production monitors", (
        Entry("auto mode", "sonnet 5", "Claude Code's production monitor"),
        Entry("guardian", "gpt 5.6 luna", "approximates Codex's production monitor"),
    )),
    Group("experimental monitors", (
        Entry("guardian strict", "gpt 5.6 luna", "guardian, monitors *all* edits"),
        Entry("auto mode ++", "opus 4.8", "auto mode with all-edit monitoring, bug fixes, "
                                          "anti-injection and compaction monitoring"),
        Entry("auto mode strict", "opus 4.8", "only the last agentic stage of auto mode ++"),
    )),
)

_WRAPS = range(18, 61)  # candidate gloss wraps, in characters — `_solve` picks among these
_PAD_X = 0.07      # axes fraction, from the card's edge to the text
_FILL = 0.92       # of the card's height the block takes, the rest split top and bottom

# The panel's vertical rhythm, in LINE UNITS rather than axes fractions: the block is measured
# first and the unit solved for afterwards, so it always fills the same share of the card and the
# spacing does not drift when a gloss gains a line. Everything is a multiple of one unit — the
# thing an ad-hoc cursor of magic decimals cannot promise.
_HEADING = 1.0      # the group heading
_UNDER_RULE = 0.55  # heading baseline to its rule, and the rule to the first name
_NAME = 0.98        # a monitor name
_GLOSS = 0.86       # one wrapped line of gloss
_AFTER_ENTRY = 0.4  # between one entry and the next
_BETWEEN_GROUPS = 0.9
_LEADING = 1.26     # a line's height as a multiple of its type size, so the unit sets the type


_EMPHASIS = re.compile(r"\*([^*\s]+)\*")


def _italicise(line: str) -> str:
    """`*word*` in a gloss becomes mathtext italic — the wrap can't split it, it holds no space."""
    return _EMPHASIS.sub(lambda match: rf"$\it{{{match.group(1)}}}$", line)


def _gloss_lines(entry: Entry, width: int) -> list[str]:
    """Wrap the gloss, then rewrap as narrow as that same line count allows.

    `fill` is greedy — it packs every line to the margin and leaves the last one short, which on a
    three-line gloss reads as a ragged step down. Re-wrapping at the narrowest width that still
    fits in the same number of lines evens them out at no cost in height.
    """
    lines = fill(entry.caption, width).splitlines()
    for narrower in range(1, width):
        balanced = fill(entry.caption, narrower).splitlines()
        if len(balanced) == len(lines):
            return balanced
    return lines


def _units(groups: tuple[Group, ...], width: int) -> float:
    """The block's height in line units, so `draw_key` can solve for the unit that fills it."""
    total = 0.0
    for index, group in enumerate(groups):
        total += _BETWEEN_GROUPS if index else 0.0
        total += _HEADING + 2 * _UNDER_RULE
        for entry in group.entries:
            total += _NAME + _GLOSS * len(_gloss_lines(entry, width)) + _AFTER_ENTRY
    return total - _AFTER_ENTRY


_REF_PT = 10.0  # a line is measured once at this size; advance widths scale with the type size


def _inches_per_point(ax: Axes, text: str, weight: str) -> float:
    """How wide the line runs per point of type — measured, since guessing at it is how text
    overflows a card that the arithmetic said would hold it."""
    figure = ax.figure
    artist = figure.text(0, 0, text, fontsize=_REF_PT, fontweight=weight)
    inches = artist.get_window_extent().width / figure.dpi
    artist.remove()
    return inches / _REF_PT


def _solve(ax: Axes, groups: tuple[Group, ...]) -> tuple[int, float]:
    """The wrap width whose type comes out largest with the block still inside the card.

    Wrap and type size trade against each other: a wider wrap spends fewer lines, which buys height
    for the type, but the larger type then has to fit back inside the card's width. Searching the
    two together lands on the largest legible type, where a hand-set wrap leaves the card half
    empty in one direction or overflowing in the other.
    """
    box = ax.get_window_extent()
    card = box.width / ax.figure.dpi * (1 - 2 * _PAD_X)
    height = box.height / ax.figure.dpi * 72

    measured: dict[tuple[str, str], float] = {}

    def per_point(text: str, weight: str) -> float:
        if (text, weight) not in measured:
            measured[text, weight] = _inches_per_point(ax, text, weight)
        return measured[text, weight]

    best = (_WRAPS.start, 0.0)
    for width in _WRAPS:
        # the unit the block would need to fill the card at this wrap, capped so a short key keeps
        # the figure's own type size rather than swelling past it
        points = min(SIZE, _FILL * height / (_units(groups, width) * _LEADING))
        fits = True
        for group in groups:
            fits &= per_point(group.heading, "bold") * points * _HEADING <= card
            for entry in group.entries:
                fits &= per_point(entry.monitor, "bold") * points * _NAME <= card
                for line in _gloss_lines(entry, width):
                    fits &= per_point(line, "normal") * points * _GLOSS <= card
        if fits and points > best[1]:
            best = (width, points)
    return best


def draw_key(ax: Axes, groups: tuple[Group, ...] = MONITOR_KEY) -> None:
    """The key panel: a bordered card, each group headed over a rule, each monitor over its gloss.

    The border is what makes it a panel rather than a caption that wandered into the figure — and
    with `align_panel` squaring the card to the plot beside it, the two read as one spread. The
    block is centred in the card, so the slack a shorter key leaves is split top and bottom rather
    than pooling at the bottom.

    Call it AFTER `align_panel`: the type is solved from the card's height, so the card has to be
    at its final size when it is drawn.

    Headings are ink over a grey rule rather than coloured, since on the figures that carry this
    key colour already means attack class and a second meaning would collide with it. The gloss
    sits in muted ink under the name it explains, so name and explanation are told apart by weight
    and colour rather than by size alone.
    """
    ax.axis("off")
    ax.add_patch(Rectangle((0, 0), 1, 1, transform=ax.transAxes, facecolor=SURFACE,
                           edgecolor=GRID, linewidth=1.4, zorder=0, clip_on=False))

    left, right = _PAD_X, 1 - _PAD_X
    wrap, points = _solve(ax, groups)
    unit = _FILL / _units(groups, wrap)
    heading_pt, name_pt, gloss_pt = points * _HEADING, points * _NAME, points * _GLOSS
    y = 0.5 + _FILL / 2

    for index, group in enumerate(groups):
        if index:
            y -= _BETWEEN_GROUPS * unit
        ax.text(left, y, group.heading, transform=ax.transAxes, ha="left", va="top",
                fontsize=heading_pt, fontweight="bold", color=INK)
        y -= (_HEADING + _UNDER_RULE) * unit
        ax.plot([left, right], [y, y], transform=ax.transAxes, color=GRID, linewidth=2)
        y -= _UNDER_RULE * unit
        for entry in group.entries:
            ax.text(left, y, entry.monitor, transform=ax.transAxes, ha="left", va="top",
                    fontsize=name_pt, fontweight="bold", color=INK)
            y -= _NAME * unit
            for line in _gloss_lines(entry, wrap):
                ax.text(left, y, _italicise(line), transform=ax.transAxes, ha="left", va="top",
                        fontsize=gloss_pt, color=MUTED)
                y -= _GLOSS * unit
            y -= _AFTER_ENTRY * unit


def align_panel(panel: Axes, plot: Axes) -> None:
    """Square a side panel's top and bottom to the plot's — call after `tight_layout`.

    `tight_layout` shrinks the plot to make room for its ticks, label and legend but leaves an
    undecorated side panel at full height, which floats the panel's middle above the plot's. This
    puts them back on one baseline.
    """
    panel_box, plot_box = panel.get_position(), plot.get_position()
    panel.set_position((panel_box.x0, plot_box.y0, panel_box.width, plot_box.height))


def draw_group_split(ax: Axes, spans: list[tuple[float, float, str]]) -> None:
    """Name each group of bars at the top of the plot, with a dashed rule between the groups.

    A rule rather than a tint: shading the two regions reads as a value the bars sit on, and on a
    figure whose whole point is height-off-a-common-axis that is exactly the wrong suggestion. The
    names sit just clear of the top spine, where no bar can reach them.
    """
    blended = mtransforms.blended_transform_factory(ax.transData, ax.transAxes)
    for left, right, heading in spans:
        ax.text((left + right) / 2, 1.012, heading, transform=blended, ha="center", va="bottom",
                fontsize=SIZE - 2, fontweight="bold", color=MUTED)
    for before, after in zip(spans, spans[1:]):
        ax.axvline((before[1] + after[0]) / 2, color=MUTED, linestyle=(0, (5, 4)), linewidth=1.2,
                   zorder=1)
