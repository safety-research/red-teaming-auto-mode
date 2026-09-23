#!/bin/bash
#SBATCH --job-name=evalkit-provider-compare
#SBATCH --no-sandbox
#SBATCH --reason="generates predictions against api.anthropic.com and api.openai.com"
#SBATCH --time=3600
# Q3 provider comparison. Regenerates predictions for the arith + summarization cells
# against both hosted models so the cached baseline can be re-benchmarked.
#
# Unsandboxed because the cells call provider endpoints; the default netns has no route.
# Keys come from the submitting environment via jobctl (ANTHROPIC_API_KEY / OPENAI_API_KEY),
# so nothing is written into this script.
set -uo pipefail

KIT=/mnt/shared/evalkit
OUT=/mnt/shared/evalkit-results
mkdir -p "$OUT"

rc=0
for cfg in "$KIT"/configs/provider_*.json; do
  echo "=== $(basename "$cfg")"
  python3 "$KIT/run_eval.py" --config "$cfg" --out "$OUT" || { rc=1; echo "  cell FAILED"; }
done

python3 "$KIT/summarize.py" --results "$OUT" --out "$OUT/summary.md" || rc=1
exit $rc
