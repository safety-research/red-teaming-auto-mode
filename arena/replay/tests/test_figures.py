"""The figure tier's regression oracle.

Three properties, each of which has a real failure behind it:

1. **Every figure redraws byte-identically** from the committed JSON. This is the whole
   contract: `data/<figure>.json` is the reduction that travels, and a redraw that does
   not reproduce the committed PNG means the reduction and the picture have drifted
   apart. Byte comparison is safe because `plot = ["matplotlib==3.11.1"]` pins the
   renderer exactly (D-78); a floated matplotlib would make this red for a reason that
   has nothing to do with the numbers.

2. **No builder contains a measured value.** The pipeline's stated contract
   is that every number arrives from the JSON. Prose cannot
   enforce that, so this checks it: any float literal in a builder that also appears as
   a measured value in that figure's own data file is a number someone typed in.

3. **INPUTS.json matches the bytes on disk**, when the source tree is reachable. The
   91 MB of run artifacts behind these figures do not travel (M-5), so a clone can only
   AUDIT the reduction. When the tree is absent this SKIPS BY NAME -- it never passes
   quietly, which would turn "I could not check" into "I checked".
"""
from __future__ import annotations

import ast
import hashlib
import importlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

FIGURES = Path(__file__).resolve().parents[1] / "figures"
sys.path.insert(0, str(FIGURES))

import figlib
import inputs as inputs_mod
from make_all import FIGURES as FIGURE_INTENTS
from make_all import VIEW_OF, data_file_for

ALL_FIGURES = sorted(FIGURE_INTENTS)

# A literal is exempt by CONSTRUCT, not by value. An allowlist of values is how this
# test would stop working: `alpha=0.85` and an ASR of 0.85 are the same float, so
# matching on value alone flags six styling constants and teaches the reader to widen
# the allowlist until nothing is caught. Instead:
#
#   * a literal inside a keyword argument (alpha=, lw=, fontsize=, left=) is layout;
#   * anything else that also appears as a measured value in the data file is suspect,
#     and needs an explicit inline marker saying why it is not a measurement.
#
# Assignment RHS is deliberately NOT exempt. It was, and that was the hole: binding a measured
# value to a name (`x = 85.5`) and plotting `x` defeated the whole check.
EXEMPT_MARKER = "# not-a-measurement"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _committed_pngs() -> dict[str, str]:
    return {p.name: _sha(p) for p in sorted((FIGURES / "out").glob("*.png"))}


@pytest.fixture(autouse=True, scope="session")
def _out_dir_is_read_only_to_the_suite():
    """No test may write into figures/out/ — it is the artifact the suite GRADES.

    This is a guard on the guard. A test that renders into the committed output directory
    redefines the reference it is comparing against, so genuine drift is red exactly once and
    green forever after; six independent reviewers found that failure here before this existed.
    Session-scoped and autouse so it covers tests nobody has written yet.
    """
    before = _committed_pngs()
    yield
    after = _committed_pngs()
    changed = sorted(k for k in before if before[k] != after.get(k))
    assert not changed, (
        f"the test suite modified committed figures: {changed}. A test must render into "
        f"tmp_path (set $REPLAY_FIGURE_OUT), never into replay/figures/out/ — writing there "
        f"turns the byte oracle into a rubber stamp."
    )


def _measured_floats(obj, out: set[float]) -> set[float]:
    """Every non-integral float anywhere in a data file: the measured values.

    Each is recorded at BOTH scales, because every builder here plots rates as percentages
    (`100 * r["auc_asr_mean"]`). Matching only the stored scale missed the obvious hardcode —
    typing `85.5` while the file says `0.855` — which is precisely D-78's worked example.

    The ×100 twin is only added when the stored value is precise enough that a collision with a
    layout constant is implausible (>= 3 decimals). Without that guard, stored values like 0.25
    and 0.5 admit 25 and 50, and the check starts firing on axis ticks.
    """
    if isinstance(obj, bool):
        return out
    if isinstance(obj, float) and obj != int(obj):
        out.add(obj)
        if round(obj, 3) != round(obj, 2):
            out.add(obj * 100)
    elif isinstance(obj, dict):
        for v in obj.values():
            _measured_floats(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _measured_floats(v, out)
    return out


@pytest.mark.parametrize("name", ALL_FIGURES)
def test_figure_redraws_byte_identical(name, tmp_path, monkeypatch):
    committed = FIGURES / "out" / f"{name}.png"
    assert committed.exists(), f"no committed figure to compare against: {committed}"

    monkeypatch.setattr(figlib, "OUTDIR", tmp_path)
    mod = importlib.import_module(f"builders.{name}")
    redrawn = mod.build()

    assert _sha(redrawn) == _sha(committed), (
        f"{name}.png does not reproduce from replay/figures/data/"
        f"{VIEW_OF.get(name, name)}.json.\n"
        f"  committed {committed.stat().st_size} B, redrawn {redrawn.stat().st_size} B\n"
        f"  Either the data file changed without the figure being rebuilt, or the "
        f"builder changed. Rebuild with: replay/figures/make_all.py --only {name}"
    )


def _bare_scalars(node) -> list[ast.Constant]:
    """The Constants, if `node` is a bare numeric literal — or a choice between two of them.

    Deliberately NOT a subtree walk. `alpha=0.9 if story else 0.45` is still layout, but
    `ax.bar(x, [85.5], w)` and `fin = [100.0, 96.5, 85.5]` are not, and a walk cannot tell them
    apart. Only a scalar, an optionally-negated scalar, and a conditional between two of those.
    """
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        node = node.operand
    if isinstance(node, ast.Constant):
        return [node]
    if isinstance(node, ast.IfExp):
        branches = _bare_scalars(node.body) + _bare_scalars(node.orelse)
        return branches if len(branches) == 2 else []
    return []


def _layout_literals(tree: ast.AST) -> set[int]:
    """ids() of Constant nodes that are layout, not data: keyword args and scalar assignments.

    Exempts only a BARE scalar — never a whole subtree. Walking the subtree (the obvious
    implementation) exempts `fin = [100.0, 96.5, 85.5]` and `ax.bar(x, [85.5], w)` too, which is
    exactly the shape a hardcoded result takes, so the check passed on a builder whose numbers had
    been typed in by hand.
    """
    exempt: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                exempt.update(id(c) for c in _bare_scalars(kw.value))
    return exempt


@pytest.mark.parametrize("name", ALL_FIGURES)
def test_builder_contains_no_measured_value(name):
    """A number in a builder is a number that can drift away from the data file.

    The byte-identity test above cannot catch this: a builder that hardcodes 85.5%
    instead of reading it redraws the committed PNG perfectly, because the PNG was
    drawn by the same hardcode. This is the only check that would notice.
    """
    path = FIGURES / "builders" / f"{name}.py"
    src = path.read_text()
    lines = src.splitlines()
    tree = ast.parse(src)
    exempt = _layout_literals(tree)

    measured = _measured_floats(json.loads(data_file_for(name).read_text()), set())
    if not measured:
        pytest.skip(
            f"{data_file_for(name).name} holds no non-integral float, so this check has zero "
            f"power for {name}: every measured value there is a count or a whole percentage, and "
            f"nothing a builder could hardcode would be caught. Reporting that honestly rather "
            f"than passing — the same rule test_inputs_manifest_matches_disk follows."
        )
    baked = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant)
                and isinstance(node.value, (int, float))
                and not isinstance(node.value, bool)):
            continue
        if id(node) in exempt or float(node.value) not in measured:
            continue
        if EXEMPT_MARKER in lines[node.lineno - 1]:
            continue
        baked.append((node.lineno, node.value, lines[node.lineno - 1].strip()))

    assert not baked, (
        f"builders/{name}.py uses literals that also appear as measured values in "
        f"{data_file_for(name).name}:\n"
        + "\n".join(f"    line {ln}: {val!r} in  {text}" for ln, val, text in baked)
        + f"\n  Every number must come from the data file via figlib.require() "
          f"If it genuinely is not a measurement, say so "
          f"inline with '{EXEMPT_MARKER}'."
    )


def _perturb(obj, factor: float = 1.37):
    """Scale every number in a payload, leaving strings and structure alone."""
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, (int, float)):
        return obj * factor
    if isinstance(obj, dict):
        return {k: _perturb(v, factor) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_perturb(v, factor) for v in obj]
    return obj


@pytest.mark.parametrize("name", ALL_FIGURES)
def test_figure_is_a_function_of_its_data(name, tmp_path, monkeypatch):
    """Change the data, and the picture MUST change.

    This is the half of "the figures come from just the data" that nothing else establishes.
    Byte-identity proves the data is SUFFICIENT — redrawing reproduces the committed PNG with no
    source tree on the machine. It cannot prove the data is NECESSARY: a builder that ignored its
    data file and drew constants would reproduce its own committed PNG perfectly, forever.

    So: perturb every number in the data file and require the render to differ. A figure that
    renders identically from different numbers is not reading them.
    """
    src = data_file_for(name)
    payload = json.loads(src.read_text())

    monkeypatch.setattr(figlib, "OUTDIR", tmp_path)
    baseline = _sha(importlib.import_module(f"builders.{name}").build())

    perturbed = tmp_path / "data"
    perturbed.mkdir(exist_ok=True)
    (perturbed / src.name).write_text(json.dumps(_perturb(payload), ensure_ascii=False))
    monkeypatch.setattr(figlib, "DATADIR", perturbed)
    after = _sha(importlib.import_module(f"builders.{name}").build())

    assert after != baseline, (
        f"{name}.png is byte-identical after every number in {src.name} was scaled by 1.37. "
        f"The builder is not reading its data — whatever it draws is coming from somewhere else, "
        f"so the committed PNG is not reproducible FROM the committed data."
    )


def test_every_figure_has_data_or_is_declared_a_view():
    for name in ALL_FIGURES:
        own = FIGURES / "data" / f"{name}.json"
        assert own.exists() or name in VIEW_OF, (
            f"{name} has no data file and is not declared in make_all.VIEW_OF; it would "
            f"render from nothing"
        )
        assert data_file_for(name).exists()


def test_no_input_escapes_its_declared_tree():
    """An input must live inside the tree it is filed under.

    The rescued source tree once symlinked one logs dir under another, so two inputs
    hashed correctly while being filed under the wrong tree — provenance that is true on this
    machine and false on every other one, and which the digest check happily passed.
    """
    manifest = json.loads((FIGURES / "INPUTS.json").read_text())
    escaped = [
        (figure, rec["path"], rec["tree"], str(actual))
        for figure, recs in manifest["inputs"].items()
        for rec in recs
        if (actual := inputs_mod.escapes_its_tree(rec["tree"], rec["path"])) is not None
    ]
    assert not escaped, (
        "inputs filed under a tree they do not resolve inside:\n"
        + "\n".join(f"    {f}: {p} (tree {t!r}) -> {a}" for f, p, t, a in escaped)
    )


def test_inputs_manifest_matches_disk():
    manifest = json.loads((FIGURES / "INPUTS.json").read_text())
    absent, checked = [], 0
    for figure, recs in manifest["inputs"].items():
        for rec in recs:
            path = inputs_mod.resolve(rec["tree"], rec["path"])
            if "sha256" not in rec or not path.exists():
                absent.append(f"{figure}:{rec['path']} (tree {rec['tree']!r})")
                continue
            assert _sha(path) == rec["sha256"], (
                f"{rec['path']} has changed since INPUTS.json was written; the committed "
                f"data/{figure}.json was derived from different bytes"
            )
            checked += 1
    if absent:
        # Skip on ANY unverified input, not only on total absence. `and not checked` meant a
        # manifest where one file resolved and fifty did not reported green, which turns
        # "I could not check" into "I checked" — the exact substitution this manifest exists to
        # prevent. A real digest mismatch still fails, because the asserts run above this.
        pytest.skip(
            f"verified {checked} of {checked + len(absent)} recorded inputs; NOT verified: "
            + "; ".join(absent)
            + "  (set $REPLAY_FIGURE_SOURCE / $FIGURE_SOURCE to audit the reduction)"
        )


def test_plot_only_path_needs_no_source_tree(tmp_path):
    """Plotting must work on a checkout that has none of the raw inputs."""
    # A SUBPROCESS, not monkeypatched attributes. Patching figlib.SOURCE_REPO pins almost
    # nothing: earlier tests have already imported every builder, so a module-scope path capture
    # survives in sys.modules, and any code reading os.environ directly never sees the patch.
    # A fresh interpreter with the env vars pointed at nothing is the only version of this test
    # that fails when the plot path grows a dependency on a tree a clone will not have.
    env = {
        **os.environ,
        "REPLAY_FIGURE_SOURCE": str(tmp_path / "nonexistent"),
        "FIGURE_SOURCE": str(tmp_path / "also-nonexistent"),
        # Render into tmp. Without this the subprocess rewrote the committed PNGs that
        # test_figure_redraws_byte_identical grades against, so a corrupted data file was red on
        # the first run and green on every run after it.
        "REPLAY_FIGURE_OUT": str(tmp_path / "out"),
    }
    r = subprocess.run(
        [sys.executable, str(FIGURES / "make_all.py")],
        env=env, cwd=tmp_path, capture_output=True, text=True, check=False,
    )
    assert r.returncode == 0, (
        f"plotting failed with no source trees on disk — the plot path has grown a dependency "
        f"on something a bare clone will not have.\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )
    assert f"{len(ALL_FIGURES)}/{len(ALL_FIGURES)} figures built" in r.stdout, r.stdout


def test_missing_data_file_fails_loudly(tmp_path, monkeypatch):
    """A hole must name the file, never render as zero."""
    monkeypatch.setattr(figlib, "DATADIR", tmp_path)
    with pytest.raises(figlib.MissingInput) as exc:
        figlib.load("injection_exists")
    assert "injection_exists.json" in str(exc.value)


def test_require_never_defaults_a_measured_quantity():
    with pytest.raises(figlib.MissingInput):
        figlib.require({"asr": None}, "asr", "test")
    with pytest.raises(figlib.MissingInput):
        figlib.require({}, "asr", "test")
    assert figlib.require({"asr": 0.0}, "asr", "test") == 0.0


def test_no_stale_output_left_behind():
    """Every committed PNG belongs to a declared figure."""
    stray = {p.stem for p in (FIGURES / "out").glob("*.png")} - set(ALL_FIGURES)
    assert not stray, f"orphan figures in replay/figures/out: {sorted(stray)}"
    shutil.rmtree(FIGURES / "__pycache__", ignore_errors=True)
