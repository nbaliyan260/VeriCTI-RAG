"""Character-window chunker with sentence-boundary snapping.

Chunks preserve exact ``start_char`` / ``end_char`` offsets so that every
downstream STIX entity, ATT&CK mapping, and Sigma rule can be linked back
to the original report text.
"""

from __future__ import annotations

import hashlib
import re
from typing import List

from ..core.config import get_settings
from ..core.schemas import Chunk


_SENT_END = re.compile(r"[.!?]\s+")


def _snap_forward(text: str, idx: int, max_jump: int = 80) -> int:
    """Snap forward to the next sentence boundary, bounded by ``max_jump``."""
    window = text[idx : idx + max_jump]
    m = _SENT_END.search(window)
    if not m:
        return min(idx, len(text))
    return idx + m.end()


def chunk_text(text: str, doc_id: str, *, size: int | None = None,
               overlap: int | None = None) -> List[Chunk]:
    """Split ``text`` into Chunk objects.

    The chunker is intentionally simple and deterministic so that test
    fixtures are stable.
    """
    s = get_settings()
    size = size or s.chunk_size
    overlap = overlap or s.chunk_overlap

    text = text or ""
    if not text.strip():
        return []

    chunks: List[Chunk] = []
    i = 0
    idx = 0
    while i < len(text):
        end = min(len(text), i + size)
        end = _snap_forward(text, end)
        body = text[i:end]
        chunk_hash = hashlib.sha1(f"{doc_id}:{i}:{end}".encode()).hexdigest()[:10]
        chunks.append(
            Chunk(
                chunk_id=f"{doc_id}_chunk{idx:03d}_{chunk_hash}",
                doc_id=doc_id,
                text=body,
                start_char=i,
                end_char=end,
                metadata={},
            )
        )
        idx += 1
        if end >= len(text):
            break
        i = max(end - overlap, i + 1)
    return chunks
