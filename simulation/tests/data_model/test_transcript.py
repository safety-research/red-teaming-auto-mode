"""Load the adapted afp sample fixtures into `Transcript`."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from auto_mode_eval.data_model import Transcript

RESOURCES = Path(__file__).parent / "resources"


@pytest.mark.parametrize("path", sorted(RESOURCES.glob("*.yaml")), ids=lambda p: p.stem)
def test_load_transcript(path: Path) -> None:
    data = yaml.safe_load(path.read_text())
    Transcript.model_validate(data)
