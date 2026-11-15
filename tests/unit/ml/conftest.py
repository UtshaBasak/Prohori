# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""A data directory holding the synthetic fixture datasets, as ``data/raw/<dataset>/``."""

import shutil
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "ml"


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    root = tmp_path / "data"
    for name in ("unsw-nb15", "cicids2017"):
        shutil.copytree(FIXTURES / "raw" / name, root / "raw" / name)
    return root
