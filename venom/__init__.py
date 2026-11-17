__version__ = "0.1.0"

import os
from pathlib import Path as _Path

def _extend_path():
    home = _Path.home()
    extra = [
        str(home / ".local" / "share" / "infer" / "bin"),
        str(home / ".local" / "share" / "codeql"),
        str(home / ".local" / "bin"),
    ]
    current = os.environ.get("PATH", "")
    for p in extra:
        if os.path.isdir(p) and p not in current:
            current = p + ":" + current
    os.environ["PATH"] = current

_extend_path()
