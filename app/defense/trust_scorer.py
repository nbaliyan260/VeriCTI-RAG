"""Source trust scoring.

Combines:
* an *initial* trust score attached to the document at ingestion (varies by
  source_type), and
* a small consistency adjustment based on how often the document agrees with
  other documents about shared entities.

Pure function – no I/O – so it is easy to unit-test.
"""

from __future__ import annotations

from typing import Dict, Iterable, List

SOURCE_TYPE_BASE = {
    "government": 0.9,
    "vendor_blog": 0.7,
    "academic": 0.8,
    "community": 0.5,
    "unknown": 0.4,
}


def initial_trust(source_type: str) -> float:
    return SOURCE_TYPE_BASE.get((source_type or "unknown").lower(), 0.4)


def adjust_trust(base: float, agreement_ratio: float) -> float:
    """``agreement_ratio`` in [0,1] = fraction of entities agreed-on by peers."""
    return max(0.0, min(1.0, base + 0.2 * (agreement_ratio - 0.5)))


def trust_score_for_documents(documents: Iterable[Dict]) -> Dict[str, float]:
    out: Dict[str, float] = {}
    docs: List[Dict] = list(documents)
    for d in docs:
        out[d["doc_id"]] = float(d.get("trust_score") or initial_trust(d.get("source_type", "unknown")))
    return out
