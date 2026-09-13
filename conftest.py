"""Shared pytest fixtures. Presence at the project root also makes
`import logsentinel` / `import app` work when running pytest."""

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import pytest

from app import create_app


@pytest.fixture()
def client(tmp_path):
    """Flask test client with an isolated per-test storage directory."""
    app = create_app(data_dir=str(tmp_path / "data"), secret_key="test-secret")
    with app.test_client() as test_client:
        yield test_client
