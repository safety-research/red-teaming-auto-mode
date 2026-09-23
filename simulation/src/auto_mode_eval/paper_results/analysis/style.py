"""One palette and one typographic scale for every figure in `figures/`.

A figure that leaves for the page is struck at `SCALE` times matplotlib's default, so it
survives being shrunk into a column; `BASE` is the size the exploratory panels beside it keep.
Grey survives only on gridlines and error bars, where it is furniture rather than text.
"""

from __future__ import annotations

SURFACE = "#ffffff"  # the page, and the gap between cells of a heatmap
INK = "#000000"  # every mark carrying a number or a name
GRID = "#d9d8d4"  # gridlines and rules
MUTED = "#5a5a55"  # supporting prose — a gloss under the name it explains
BAND = "#e7e6e2"  # a summary drawn behind the marks it summarises
BLANK = "#f1f0ec"  # a cell with nothing measured behind it
EDGE = "#ffffff"  # bar outline, so neighbours part

# a bar chart's two families: the monitors as deployed, and the variants this work proposes
DEPLOYED = "#2a78d6"
PROPOSED = "#2e7d4f"

# One hue per attack class, keyed as `tables.ATTACK_CLASSES` keys them so neither can be reordered
# into the other's colours — `panels` refuses to draw if the two ever drift apart.
#
# Re-stepped from the hues the figure was drafted in: the draft's `#1F4288` sat below the
# lightness band and its `#0F766E` below the chroma floor (it reads grey), which the validator in
# the dataviz skill fails. Crimson and amber are the draft's own; the blue and teal are the
# nearest steps that pass all six checks — lightness, chroma, CVD separation on every adjacent
# pair, the normal-vision floor, and 3:1 against the surface.
ATTACK_CLASS_COLOURS = {
    "monitor injection": "#A3323F",
    "multi-context": "#B58A2E",
    "coverage gap": "#3562C4",
    "policy failure": "#0C9184",
}

BASE = 9.0
SCALE = 2.0
SIZE = BASE * SCALE
