"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture()
def tmp_secrets_dir(tmp_path: Path) -> Path:
    d = tmp_path / "secrets"
    d.mkdir(parents=True)
    return d