"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest
from sse_starlette.sse import AppStatus


@pytest.fixture(autouse=True)
def isolate_sse_event_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    # sse-starlette 2.x keeps a process-wide event; pytest creates a loop per test.
    monkeypatch.setattr(AppStatus, "should_exit_event", None)


@pytest.fixture()
def tmp_secrets_dir(tmp_path: Path) -> Path:
    d = tmp_path / "secrets"
    d.mkdir(parents=True)
    return d
