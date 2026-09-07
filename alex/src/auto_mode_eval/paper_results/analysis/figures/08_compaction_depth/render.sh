#!/usr/bin/env sh
# The notebook is this group's only source; the `.png`s and the `.pdf` beside it are what it draws.
# It reads the frozen `episodes` frame, not the logs, so it runs anywhere the package does — rebuild
# that frame with `python -m ...analysis.tables` after blessing a run.
set -eu
cd "$(dirname "$0")"
uv run --with nbconvert jupyter nbconvert --to notebook --execute --inplace compaction_depth.ipynb
