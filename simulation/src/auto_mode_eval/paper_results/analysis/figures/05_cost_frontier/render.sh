#!/usr/bin/env sh
# The notebook is this figure's only source; the `.png`s beside it are what it draws. It reads the
# `cap`, `mb` and `fp4k` families' `.eval` files, so the runs have to be reachable — `$AFP_ROOT`,
# else the nearest parent holding a `journal/`. Minutes, not seconds: it opens whole samples.
set -eu
cd "$(dirname "$0")"
uv run --with nbconvert jupyter nbconvert --to notebook --execute --inplace cost_frontier.ipynb
