#!/bin/bash
#SBATCH --job-name=evalkit-sweep-provider
#SBATCH --no-sandbox
#SBATCH --reason="provider cells call api.anthropic.com / api.openai.com"
#SBATCH --time=1800
# The provider half of the sweep. Separate job from sweep_local.sh because these cells
# generate predictions against a hosted model instead of scoring a cached file, so they
# need outbound network — the default netns has no route.
#
# Keys come from the submitting environment via jobctl; nothing is written into this file.
set -uo pipefail

KIT=/mnt/shared/evalkit
OUT=/mnt/shared/evalkit-results
mkdir -p "$OUT"

if [ ! -d "$KIT" ]; then
  echo "sweep: $KIT missing — run ./stage.sh on the login node before submitting" >&2
  exit 2
fi

rc=0
for cfg in "$KIT"/configs/provider_*.json; do
  [ -e "$cfg" ] || { echo "sweep: no provider_*.json configs in $KIT/configs" >&2; exit 2; }
  echo "=== $(basename "$cfg")"
  python3 "$KIT/run_eval.py" --config "$cfg" --out "$OUT" || { rc=1; echo "  cell FAILED"; }
done

echo
python3 "$KIT/summarize.py" --results "$OUT" --out "$OUT/summary.md" || rc=1
exit $rc
