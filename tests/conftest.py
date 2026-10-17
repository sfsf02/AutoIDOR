"""Pytest harness for Person B's discovery tests.

Makes the repository root importable so ``python -m pytest`` behaves
identically whether it is invoked from the repo root or from ``tests/``.
This is test harness infrastructure only; no module code is affected.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
