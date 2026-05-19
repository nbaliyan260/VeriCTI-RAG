"""Load plain text / markdown CTI reports from disk or raw bytes."""

from __future__ import annotations

from pathlib import Path
from typing import Union


def load_text(path_or_bytes: Union[str, Path, bytes]) -> str:
    if isinstance(path_or_bytes, (str, Path)):
        with open(path_or_bytes, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    if isinstance(path_or_bytes, bytes):
        return path_or_bytes.decode("utf-8", errors="ignore")
    raise TypeError(f"Unsupported input type: {type(path_or_bytes)!r}")
