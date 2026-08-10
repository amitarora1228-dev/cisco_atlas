"""Shared test fixtures for Project ATLAS.

``pythonpath`` for the engine packages is configured in the root ``pyproject.toml``
so tests import them the same way the container does.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

# Importing DartHawk triggers its runtime pip install unless this is set. Tests
# must never mutate the environment they run in.
os.environ.setdefault("DARTHAWK_AUTO_INSTALL", "0")

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def client():
    """HTTP client against the unified shell, with both engines mounted."""
    from fastapi.testclient import TestClient

    from web.main import app

    with TestClient(app) as test_client:
        yield test_client
