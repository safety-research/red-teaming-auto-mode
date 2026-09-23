#!/usr/bin/env sh
# The notebook is this directory's only source; the `.png`s beside it are what it draws. It reads
# no `.eval` files — the cells are prose, the arm names come from the monitor registry — so it
# runs in seconds.
set -eu
cd "$(dirname "$0")"
uv run --with nbconvert jupyter nbconvert --to notebook --execute --inplace reference_tables.ipynb
