import os
from pathlib import Path


def load_dotenv(path: str | os.PathLike = ".env") -> None:
    """
    Minimal .env loader (no external deps).
    - Ignores blank lines and comments (# ...)
    - Supports KEY=VALUE and quoted values.
    - Does NOT override already-set environment variables.
    """
    p = Path(path)
    if not p.exists():
        return

    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        if not k:
            continue
        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
            v = v[1:-1]
        if k not in os.environ:
            os.environ[k] = v


