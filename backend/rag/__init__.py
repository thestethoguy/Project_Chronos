"""Package marker. Importing this package makes both `backend.x` and bare `x` imports resolve."""
import sys as _sys
from pathlib import Path as _Path

_b = str(_Path(__file__).resolve().parents[1])
if _b not in _sys.path:
    _sys.path.insert(0, _b)
import _bootstrap  # noqa: E402,F401  (adds <repo_root> and <repo_root>/backend to sys.path)
