#!/usr/bin/env python3
"""routecore release builder — stdlib stand-in for `python -m build`.

Builds the release WHEEL and the source distribution (sdist) from pyproject.toml and writes
both under `dist/`, exactly as `python -m build` would. Two independent file sets, matching
hatchling:

  * the WHEEL packages [tool.hatch.build.targets.wheel].packages, honoring its `exclude`, so
    an internal-only module never ships in the distributed wheel;
  * the SDIST carries the project sources + pyproject/README/PKG-INFO, honoring
    [tool.hatch.build.targets.sdist].exclude.

Usage:  python3 build_release.py     # writes dist/*.whl and dist/*.tar.gz

hatchling is not installed in this offline environment, so this stdlib builder stands in for
it; the artifact layout is the same.
"""
from __future__ import annotations

import base64
import fnmatch
import hashlib
import io
import os
import tarfile
import tomllib
import zipfile

_ROOT = os.path.dirname(os.path.abspath(__file__))
_DIST = os.path.join(_ROOT, "dist")


def _cfg():
    with open(os.path.join(_ROOT, "pyproject.toml"), "rb") as fh:
        return tomllib.load(fh)


def _target(cfg, name):
    build = cfg.get("tool", {}).get("hatch", {}).get("build", {})
    return build.get("targets", {}).get(name, {})


def _sources(roots, excludes):
    """Every file under `roots`, minus the target's exclude patterns (project-relative)."""
    out = []
    for root in roots:
        for dirpath, _dirs, files in os.walk(os.path.join(_ROOT, root)):
            for fn in sorted(files):
                if fn.endswith(".pyc") or "__pycache__" in dirpath:
                    continue
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, _ROOT).replace(os.sep, "/")
                if not any(fnmatch.fnmatch(rel, pat) for pat in excludes):
                    out.append((full, rel))
    return sorted(out, key=lambda t: t[1])


def _metadata(proj):
    return (
        "Metadata-Version: 2.1\n"
        f"Name: {proj['name']}\n"
        f"Version: {proj['version']}\n"
        f"Summary: {proj.get('description', '')}\n"
        f"Requires-Python: {proj.get('requires-python', '')}\n"
    )


def build_wheel(cfg):
    proj = cfg["project"]
    tgt = _target(cfg, "wheel")
    files = _sources(tgt.get("packages", ["src/" + proj["name"]]), tgt.get("exclude", []))
    name, ver = proj["name"], proj["version"]
    distinfo = f"{name}-{ver}.dist-info"
    path = os.path.join(_DIST, f"{name}-{ver}-py3-none-any.whl")
    record = []

    def _add(zf, arcname, data):
        zf.writestr(arcname, data)
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        record.append(f"{arcname},sha256={digest},{len(data)}")

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for full, rel in files:
            with open(full, "rb") as fh:
                data = fh.read()
            # src-layout: strip the leading "src/" so the wheel is importable as installed.
            _add(zf, rel.split("/", 1)[1] if rel.startswith("src/") else rel, data)
        _add(zf, f"{distinfo}/METADATA", _metadata(proj).encode())
        _add(zf, f"{distinfo}/WHEEL", b"Wheel-Version: 1.0\nGenerator: build_release\n"
                                      b"Root-Is-Purelib: true\nTag: py3-none-any\n")
        record.append(f"{distinfo}/RECORD,,")
        zf.writestr(f"{distinfo}/RECORD", "\n".join(record) + "\n")
    return path


def build_sdist(cfg):
    proj = cfg["project"]
    excludes = _target(cfg, "sdist").get("exclude", [])
    name, ver = proj["name"], proj["version"]
    base = f"{name}-{ver}"
    path = os.path.join(_DIST, f"{base}.tar.gz")
    extra = [f for f in ("pyproject.toml", "README.md") if os.path.exists(os.path.join(_ROOT, f))]
    files = _sources(["src"], excludes) + [(os.path.join(_ROOT, f), f) for f in extra]
    with tarfile.open(path, "w:gz") as tf:
        for full, rel in sorted(files, key=lambda t: t[1]):
            tf.add(full, arcname=f"{base}/{rel}")
        pkginfo = _metadata(proj).encode()
        info = tarfile.TarInfo(f"{base}/PKG-INFO")
        info.size = len(pkginfo)
        tf.addfile(info, io.BytesIO(pkginfo))
    return path


if __name__ == "__main__":
    os.makedirs(_DIST, exist_ok=True)
    _c = _cfg()
    print("wrote", build_wheel(_c))
    print("wrote", build_sdist(_c))
