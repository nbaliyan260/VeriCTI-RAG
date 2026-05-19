"""Test fixtures – use an isolated temp data dir per test session."""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest


@pytest.fixture(scope="session", autouse=True)
def isolated_data(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("vericti")
    os.environ["VERICTI_DATA_DIR"] = str(tmp / "data")
    os.environ["VERICTI_DB_PATH"] = str(tmp / "data" / "vericti.db")
    os.environ["VERICTI_CHROMA_DIR"] = str(tmp / "data" / "chroma")
    # Ensure the repo root is importable
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    # Re-import settings so new envs take effect
    import app.core.config as cfg

    importlib.reload(cfg)
    cfg.settings.ensure_dirs()
    yield
