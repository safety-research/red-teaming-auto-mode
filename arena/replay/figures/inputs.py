#!/usr/bin/env python3
"""The manifest of inputs the extractors read, and nothing else.

``data/<figure>.json`` is a REDUCTION: 169 KB of committed numbers standing in for the
91 MB of run artifacts, across two trees, that do not travel (M-5, "evidence travels;
its bulk does not"). A checkout of this repo can plot every figure, but it cannot
re-derive one, because the inputs are not here.

That is the correct trade, but it leaves a hole: the reduction asserts itself. This
module closes it. ``INPUTS.json`` records, for every file an extractor reads, the
path it was read from and the sha256 of the bytes that were read. A reader who has
the source tree can prove the committed JSON came from those exact bytes; a reader
who does not still learns precisely which bytes to ask for.

    python replay/figures/inputs.py            # verify INPUTS.json against disk
    python replay/figures/inputs.py --write    # regenerate it

Verification is SKIPPED, loudly and by name, for any input whose tree is absent --
never quietly passed.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from figlib import AME_RESULTS, SOURCE_REPO, sha256

MANIFEST = Path(__file__).resolve().parent / "INPUTS.json"

_RUNS = "replay/runs/informed_jsonl_text"
_SCRIPTS = "replay/scripts/informed_jsonl_text"
_PARETO = "replay/docs/experiments/2026-06-26-serialization-robustness-pareto"
_EXP = "replay/docs/experiments"

# Files an extractor CITES but never opens: they back a transcribed label, a pooling rule or a
# caption. Recording them under INPUTS would make the manifest's own sentence ("every file the
# extractors read") false, and would let a digest check report coverage it does not have --
# so they are listed separately and reported separately.
CITED: dict[str, list[tuple[str, str]]] = {
    "injection_exists": [
        ("source", f"{_SCRIPTS}/aggregate_climb.py"),
    ],
    "ladder_robustness": [
        ("source", f"{_SCRIPTS}/escaping_variants.py"),
        ("source", f"{_SCRIPTS}/aggregate_climb.py"),
    ],
}


_CAP = "src/auto_mode_eval/paper_results/analysis/results/cap"
_CAP_BRIEFS = ("compaction_attack_exfil", "compaction_attack_rogue", "coverage_gap_exfil",
               "prompt_injection_exfil", "persuasion_exfil",
               "policy_gap_exfil", "policy_gap_rogue")
_CAP_ARMS = ("original-opus48", "cascade-opus48", "agentic-opus48", "guardian-gpt56luna",
             "guardian_strict-gpt56luna", "original_severity-opus48",
             "cascade_s1.5-s3-opus48", "cascade_s1.5-s2-s3-opus48", "guardian-opus48",
             "guardian_strict-opus48", "hybrid-opus48", "hybrid_fast_allow-opus48")
# The four of 84 cells the capability eval never ran. Listed here rather than discovered by
# globbing, for the reason the whole manifest exists: a list built from what happens to be on
# disk cannot tell "never run" from "not on this machine". Listing them as inputs instead was
# worse -- four unresolvable paths turn test_inputs_manifest_matches_disk from a PASS over 133
# digests into a SKIP over all of them, which is the "I could not check" -> "I checked"
# substitution that test refuses. If one of these is ever run, delete it here and re-write.
_CAP_NEVER_RUN = {
    ("prompt_injection_exfil", "cascade_s1.5-s3-opus48"),
    ("persuasion_exfil", "cascade_s1.5-s3-opus48"),
    ("persuasion_exfil", "hybrid-opus48"),
    ("persuasion_exfil", "hybrid_fast_allow-opus48"),
}

# figure -> [(tree, path-within-tree)]. "source" = $REPLAY_FIGURE_SOURCE (the rescued
# run tree), "ame_results" = $AME_RESULTS (auto-mode-eval's paper_results, at its default branch).
INPUTS: dict[str, list[tuple[str, str]]] = {
    "injection_exists": [
        ("source", f"{_RUNS}/{fam}/{arm}/seg-001/checkpoints.jsonl")
        for fam in ("overnight", "overnight-48")
        for arm in ("text-inf", "text-blind", "jsonl-inf", "jsonl-blind")
    ] + [
        ("source", "portal/data/injection_algorithm.json"),
        # The two run writeups the gate attestation reads. They are the EVIDENCE that each
        # panel's curves came from the gate model the figure labels them with, so leaving them
        # unpinned meant the audit reported green over the basis of its own attestation.
        ("source", f"{_EXP}/2026-06-19-informed-jsonl-vs-text-opus48/README.md"),
        ("source", f"{_EXP}/2026-06-19-informed-jsonl-vs-text/README.md"),
    ],
    "injection_serialization": [
        ("source", f"{_SCRIPTS}/escaping_variants.py"),
        ("source", f"{_SCRIPTS}/aggregate_climb.py"),
        ("source", f"{_PARETO}/aggregate.json"),
    ],
    # aggregate.json is the only file this extractor OPENS; escaping_variants.py and
    # aggregate_climb.py appear in its provenance strings and are filed under CITED.
    "ladder_robustness": [
        ("source", f"{_PARETO}/aggregate.json"),
    ],
    "pareto": [
        ("source", f"{_PARETO}/token_cost.json"),
        ("source", f"{_PARETO}/aggregate.json"),
        ("source", f"{_SCRIPTS}/escaping_variants.py"),
        ("source", f"{_SCRIPTS}/aggregate_climb.py"),
    ],
    # auto-mode-eval's capability results: one YAML per (brief, arm) cell. Small enough to
    # travel and they still do not, because they are ANOTHER REPOSITORY'S deliverable --
    # `paper_results` is maintained there and vendoring a copy here would make two of them,
    # with ours quietly ageing. What travels is the reduction plus these digests, which is
    # exactly the bargain the rest of this manifest strikes with the 91 MB it cannot carry.
    "simulation_grid": [
        ("ame_results", f"{_CAP}/{brief}/{arm}.yaml")
        for brief in _CAP_BRIEFS for arm in _CAP_ARMS
        if (brief, arm) not in _CAP_NEVER_RUN
    ],
}

TREES = {"source": SOURCE_REPO, "ame_results": AME_RESULTS}


def resolve(tree: str, rel_path: str) -> Path:
    return TREES[tree] / rel_path


def escapes_its_tree(tree: str, rel_path: str) -> Path | None:
    """The real location, if this input actually lives outside the tree it is filed under.

    A rescued source tree can contain a symlink pointing outside itself, so a path
    can resolve, hash correctly, and still be filed under the wrong tree -- true on this machine
    and a lie everywhere else. Returns the resolved path when that has happened, else None.
    """
    declared, actual = TREES[tree].resolve(), resolve(tree, rel_path).resolve()
    try:
        actual.relative_to(declared)
    except ValueError:
        return actual
    return None


def _records(entries: list[tuple[str, str]]) -> list[dict]:
    recs = []
    for tree, rel_path in entries:
        path = resolve(tree, rel_path)
        rec = {"tree": tree, "path": rel_path}
        if path.exists():
            rec["bytes"] = path.stat().st_size
            rec["sha256"] = sha256(path)
        else:
            rec["absent_at_write_time"] = True
        recs.append(rec)
    return recs


def collect() -> dict:
    out = {figure: _records(entries) for figure, entries in INPUTS.items()}
    cited = {figure: _records(entries) for figure, entries in CITED.items()}
    return {
        "cited_not_read": cited,
        "what": "every file the extractors read, with the sha256 of the bytes the "
                "committed data/<figure>.json was derived from",
        "trees": {
            "source": "$REPLAY_FIGURE_SOURCE -- the rescued run tree; holds the OPRO "
                      "checkpoints (58 MB of the inputs below), the variant registry "
                      "and the portal payloads. Does not travel (M-5).",
            "ame_results": "$AME_RESULTS -- auto-mode-eval's `paper_results` package, the "
                           "source of truth for the capability (simulation) eval. NOT the "
                           "blessed submodule pin: `paper_results` does not exist there, so "
                           "this is a separate clone at the upstream default branch, and "
                           "data/simulation_grid.json records the commit it was read at. "
                           "Four of the 84 cells were never run and are absent, not zero.",
        },
        "note": "A checkout without these trees can PLOT every figure from the "
                "committed JSON but cannot re-derive one. This manifest is what "
                "makes that reduction auditable rather than merely asserted.",
        "inputs": out,
    }


def verify() -> int:
    if not MANIFEST.exists():
        print(f"missing {MANIFEST}; regenerate with --write", file=sys.stderr)
        return 1
    manifest = json.loads(MANIFEST.read_text())
    checked = skipped = bad = 0
    for figure, recs in manifest["inputs"].items():
        for rec in recs:
            path = resolve(rec["tree"], rec["path"])
            if "sha256" not in rec:
                print(f"  SKIP  {figure}: {rec['path']} (no digest recorded)")
                skipped += 1
                continue
            if not path.exists():
                print(f"  SKIP  {figure}: {rec['path']} "
                      f"(tree {rec['tree']!r} not on this machine: {path})")
                skipped += 1
                continue
            escaped = escapes_its_tree(rec["tree"], rec["path"])
            if escaped is not None:
                print(f"  BAD   {figure}: {rec['path']} is filed under tree "
                      f"{rec['tree']!r} but resolves to {escaped}", file=sys.stderr)
                bad += 1
                continue
            actual = sha256(path)
            if actual != rec["sha256"]:
                print(f"  BAD   {figure}: {rec['path']}\n"
                      f"          recorded {rec['sha256']}\n"
                      f"          on disk  {actual}", file=sys.stderr)
                bad += 1
            else:
                checked += 1
    print(f"\n{checked} verified, {skipped} skipped (tree absent), {bad} MISMATCHED")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", action="store_true", help="regenerate INPUTS.json")
    args = ap.parse_args()
    if args.write:
        MANIFEST.write_text(json.dumps(collect(), indent=1) + "\n")
        print(f"wrote {MANIFEST}")
        return 0
    return verify()


if __name__ == "__main__":
    raise SystemExit(main())
