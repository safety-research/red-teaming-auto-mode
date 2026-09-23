#!/bin/bash
#SBATCH --job-name=evalkit-sweep-local
#SBATCH --time=900
# Cached cells only: every prediction is already on disk, so this needs no network and
# runs under the default sandbox. Provider cells are a separate job -- see
# jobs/archive/ for how previous sweeps ran those.
set -uo pipefail

KIT=/mnt/shared/evalkit
OUT=/mnt/shared/evalkit-results
mkdir -p "$OUT"

if [ ! -d "$KIT" ]; then
  echo "sweep: $KIT missing — run ./stage.sh on the login node before submitting" >&2
  exit 2
fi

rc=0
for cfg in "$KIT"/configs/local_*.json; do
  [ -e "$cfg" ] || { echo "sweep: no local_*.json configs found in $KIT/configs" >&2; exit 2; }
  echo "=== $(basename "$cfg")"
  # Keep going on a failed cell: one broken config should not cost the whole sweep.
  python3 "$KIT/run_eval.py" --config "$cfg" --out "$OUT" || { rc=1; echo "  cell FAILED"; }
done

echo
python3 "$KIT/summarize.py" --results "$OUT" --out "$OUT/summary.md" || rc=1
exit $rc
