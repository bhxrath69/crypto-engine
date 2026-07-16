# Make `crypto_engine` importable during pytest runs.
# Pytest does not automatically add the project root to sys.path in all setups.

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

