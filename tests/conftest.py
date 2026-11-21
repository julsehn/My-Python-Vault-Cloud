"""Shared test setup: isolated database and clean rate-limit state."""
import os
import tempfile

os.environ.setdefault("SESSION_SECRET", "test-secret-for-unit-tests-0123456789")
os.environ.setdefault("DB_DIR", tempfile.mkdtemp(prefix="sherlock-cloud-tests-"))

import pytest


@pytest.fixture(autouse=True)
def _clear_rate_limits():
    # Import lazily so app.main sees the test environment above.
    from app.main import _auth_attempts

    _auth_attempts.clear()
    yield
    _auth_attempts.clear()
