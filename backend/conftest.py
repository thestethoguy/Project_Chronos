import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent / 'backend' if Path(__file__).parent.name != 'backend' else Path(__file__).resolve().parent))
import _bootstrap  # noqa: F401

