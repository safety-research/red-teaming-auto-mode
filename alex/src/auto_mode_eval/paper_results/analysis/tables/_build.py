"""Freezing the frames to disk, so a figure can be redrawn without the logs behind it.

The `.eval` files these come from are hundreds of megabytes and live in another checkout; the
frames are a few kilobytes and travel with the package. Rebuild after blessing a run.

Each frame is written twice. The parquet is what `load()` reads — it round-trips the nullable ints
and the nulls in a string column, which a CSV does not. The CSV is there so a rebuild shows up as
a readable diff rather than a changed blob; nothing loads it.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pandas as pd
import pandera.pandas as pa

from auto_mode_eval.paper_results.analysis.results import arm_display

from ._arena import arena_cells, arena_label, arena_rows
from ._benign import benign_cost
from ._schema import (
    BENCHMARK,
    SIMULATION,
    ArenaCells,
    BenignCost,
    EpisodeRows,
    FrontierAsr,
    HeadlineAsr,
    HeatmapCells,
    PooledAsr,
    SimulationCells,
    label,
)
from ._simulation import attacker_episodes, episode_rows, simulation_cells
from ._views import across_families, frontier, headline, heatmap

DATA = Path(__file__).resolve().parent / "data"

# what each frozen frame is validated against on the way back in
SCHEMAS: dict[str, type[pa.DataFrameModel]] = {
    "episodes": EpisodeRows,
    "attacker_episodes": EpisodeRows,
    "arena_cells": ArenaCells,
    "arena_by_env": HeatmapCells,
    "simulation_cells": SimulationCells,
    "heatmap": HeatmapCells,
    "headline": HeadlineAsr,
    "frontier": FrontierAsr,
    "across_families": PooledAsr,
    "benign_cost": BenignCost,
}
NAMES = tuple(SCHEMAS)


def _measured(name: str, measure: Callable[[], pd.DataFrame], reuse: bool) -> pd.DataFrame:
    """A frame that costs a pass over the logs: measured afresh, or lifted from the last freeze.

    `reuse` is for a change that moves no measurement — a different pooling, a new view. Naming
    alone needs neither: `load()` relabels on the way out, so a renamed design or attack reaches
    a figure with no rebuild at all.

    The two frames that pay for a pass are `episode_rows()`, which opens every capability sample,
    and `benign_cost()`, which prices every fp4k ruling. Everything else here is a view over them,
    a committed CSV, or an eval header.
    """
    return load(name) if reuse else measure()


def _row_label(row: dict) -> str:
    """A heatmap row's name, off the same pieces its builder used."""
    if row["eval_family"] == BENCHMARK:
        return str(row["row_label"])  # a corpus, named once rather than after an attack
    if row["eval_family"] == SIMULATION:
        return label(row["attack"])
    # `arena_rows` keys a pooled row by its tier and an unpooled one by its environment
    suffix = str(row["row_key"]).removeprefix(f"{row['attack']}_")
    pooled = suffix == str(row["risk"])
    return arena_label(row["attack"], risk=row["risk"], env=None if pooled else suffix)


def _labelled(frame: pd.DataFrame) -> pd.DataFrame:
    """The presentational columns recomputed from the keys they are a function of.

    `display` is what the registry calls an arm, `row_label` what `ATTACK_LABEL` calls a row.
    Both are naming rather than measurement, and a frozen frame that stored them as text would
    make renaming an attack cost a rebuild. Everything else on these frames is what happened.
    """
    if "arm" in frame.columns:
        frame = frame.assign(display=[arm_display(arm) for arm in frame.arm])
    if "row_label" not in frame.columns:
        return frame
    return frame.assign(row_label=[_row_label(row) for row in frame.to_dict("records")])


def _compute(reuse: bool = False) -> dict[str, pd.DataFrame]:
    """Every frame off one pass over the logs. `episode_rows()` reads every capability `.eval`, so
    it is made once here and pooled into `simulation_cells()` rather than each caller reading them
    again; the three views then take the heatmap rather than asking for it again."""
    attempts = _measured("episodes", episode_rows, reuse)
    simulation = simulation_cells(attempts)
    cells = heatmap(simulation)
    return {
        "episodes": attempts,
        # the paired-attacker cells, frozen apart so that nothing pooling `episodes` picks them up
        "attacker_episodes": _measured("attacker_episodes", attacker_episodes, reuse),
        "arena_cells": arena_cells(),
        "arena_by_env": arena_rows(by_env=True),
        "simulation_cells": simulation,
        "heatmap": cells,
        "headline": headline(cells),
        "frontier": frontier(cells),
        "across_families": across_families(cells),
        "benign_cost": _measured("benign_cost", benign_cost, reuse),
    }


def build(reuse: bool = False) -> None:
    """Rebuild every frozen frame and say what landed in each. `reuse` skips the capability logs
    and derives from the frozen grid — right after a rename or a pooling change, wrong after a
    run lands."""
    DATA.mkdir(exist_ok=True)
    frames = _compute(reuse)
    print()
    for name in NAMES:
        frame = frames[name]
        frame.to_parquet(DATA / f"{name}.parquet", index=False)
        frame.to_csv(DATA / f"{name}.csv", index=False)
        size = (DATA / f"{name}.parquet").stat().st_size
        print(f"{name:>17}  {len(frame):>4} rows x {len(frame.columns):>2} cols  {size / 1024:.0f}K")
    print(f"\nwrote {2 * len(NAMES)} files to {DATA}")


def load(name: str) -> pd.DataFrame:
    """A frozen frame by name, validated against the schema its live loader returns.

    `load("heatmap")` is `heatmap()` as of the last rebuild, without touching a log.
    """
    if name not in SCHEMAS:
        raise KeyError(f"no frozen frame {name!r} — have {', '.join(NAMES)}")
    frame = _labelled(pd.read_parquet(DATA / f"{name}.parquet"))
    return SCHEMAS[name].validate(frame)
