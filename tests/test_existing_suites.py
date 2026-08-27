"""Expose the repository's executable offline checks to pytest.

The original suites intentionally remain executable with ``python foo_test.py``.
Running each in a subprocess preserves that contract, isolates environment and
module state, and—most importantly—turns any non-zero suite result into a real
pytest failure instead of hiding it during collection.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SUITES = ("smoke_test.py", "sweep_test.py", "scamscan_test.py", "web_test.py")


@pytest.mark.parametrize("suite", SUITES)
def test_existing_offline_suite(suite: str) -> None:
    completed = subprocess.run(
        [sys.executable, suite],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert completed.returncode == 0, (
        f"{suite} exited {completed.returncode}\n"
        f"--- stdout ---\n{completed.stdout}\n"
        f"--- stderr ---\n{completed.stderr}"
    )
