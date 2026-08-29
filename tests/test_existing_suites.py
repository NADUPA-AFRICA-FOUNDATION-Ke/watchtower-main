"""Expose the repository's executable offline checks to pytest.

The original suites intentionally remain executable with ``python foo_test.py``.
Running each in a subprocess preserves that contract, isolates environment and
module state, and—most importantly—turns any non-zero suite result into a real
pytest failure instead of hiding it during collection.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SUITES = ("smoke_test.py", "sweep_test.py", "scamscan_test.py", "web_test.py")
CREDENTIAL_ENV = {
    "GEMINI_API_KEY", "ANTHROPIC_API_KEY", "OPENSANCTIONS_API_KEY",
    "BRAVE_API_KEY", "OPENCORPORATES_API_KEY", "BLUESKY_HANDLE",
    "BLUESKY_APP_PASSWORD", "REDDIT_CLIENT_ID", "REDDIT_CLIENT_SECRET",
    "X_BEARER_TOKEN", "SOCIALCRAWL_API_KEY", "TIKTOK_ACCESS_TOKEN",
    "DATABASE_URL",
}


@pytest.mark.parametrize("suite", SUITES)
def test_existing_offline_suite(suite: str) -> None:
    env = {key: value for key, value in os.environ.items()
           if key not in CREDENTIAL_ENV}
    # The executable suites must not reload a developer's real .env after we
    # sanitize the inherited process environment.
    env["WATCHTOWER_SKIP_DOTENV"] = "1"
    completed = subprocess.run(
        [sys.executable, suite],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
        env=env,
    )
    assert completed.returncode == 0, (
        f"{suite} exited {completed.returncode}\n"
        f"--- stdout ---\n{completed.stdout}\n"
        f"--- stderr ---\n{completed.stderr}"
    )
