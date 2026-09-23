#!/usr/bin/env sh
# `.dot` is the figure's only source; both outputs beside it are generated. 160 dpi is what the
# slides are laid out against — the pdf is the vector the paper takes.
set -eu
cd "$(dirname "$0")"
dot -Tpng -Gdpi=160 compaction_attack.dot -o compaction_attack.png
dot -Tpdf compaction_attack.dot -o compaction_attack.pdf
