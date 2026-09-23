#!/usr/bin/env python3
"""Collate results/*.json into a markdown comparison table.

    python3 summarize.py --results /mnt/shared/evalkit-results \
                         --out /mnt/shared/evalkit-results/summary.md
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description="collate eval results")
    ap.add_argument("--results", default="/mnt/shared/evalkit-results")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    rdir = Path(args.results)
    if not rdir.is_dir():
        print(f"summarize: no results dir at {rdir}", file=sys.stderr)
        return 1

    rows = []
    for p in sorted(rdir.glob("*.json")):
        try:
            rows.append(json.loads(p.read_text(encoding="utf-8")))
        except ValueError:
            print(f"summarize: skipping unparseable {p.name}", file=sys.stderr)
    if not rows:
        print(f"summarize: no result files in {rdir}", file=sys.stderr)
        return 1

    lines = [
        "# Eval sweep summary",
        "",
        f"Generated {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} "
        f"from {len(rows)} cell(s) in `{rdir}`.",
        "",
        "| cell | task | model | mode | n | accuracy |",
        "|---|---|---|---|---:|---:|",
    ]
    for r in sorted(rows, key=lambda r: (r.get("task") or "", r.get("name") or "")):
        acc = r.get("accuracy")
        lines.append(
            f"| {r.get('name','?')} | {r.get('task','?')} | {r.get('model','?')} | "
            f"{r.get('mode','?')} | {r.get('n',0)} | "
            f"{'n/a' if acc is None else f'{acc:.3f}'} |"
        )

    scored = [r["accuracy"] for r in rows if r.get("accuracy") is not None]
    if scored:
        lines += ["", f"Mean accuracy across {len(scored)} scored cell(s): "
                      f"**{sum(scored)/len(scored):.3f}**"]
    missing = [r["name"] for r in rows if r.get("n_missing")]
    if missing:
        lines += ["", f"Cells with unscored items: {', '.join(missing)}"]

    text = "\n".join(lines) + "\n"
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out} ({len(rows)} cells)")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
