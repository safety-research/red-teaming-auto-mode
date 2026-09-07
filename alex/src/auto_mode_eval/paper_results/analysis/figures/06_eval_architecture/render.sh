#!/usr/bin/env sh
# The two `.dot`s are this directory's only sources; every output beside them is generated. 160
# dpi is what the slides are laid out against — the pdf is the vector the paper takes.
set -eu
cd "$(dirname "$0")"
for name in fuzzing_pipeline simulation_loop; do
  dot -Tpng -Gdpi=160 "$name.dot" -o "$name.png"
  dot -Tpdf "$name.dot" -o "$name.pdf"
done
