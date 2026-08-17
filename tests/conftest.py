import sys
from pathlib import Path

# The repo is not an installed package ([tool.uv] package = false), so put the
# repo root on sys.path to make `import config` / `from src.xxx import ...` work.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
