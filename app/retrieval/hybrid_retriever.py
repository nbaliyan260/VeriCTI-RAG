"""Hybrid retriever = alpha * vector + (1-alpha) * BM25, with trust/freshness re-weighting."""

from __future__ import annotations

from typing import List, Optional, Tuple

from ..core.config import get_settings
from ..core.db import get_document
from .bm25_retriever import BM25Retriever
from .vector_retriever import VectorRetriever


def _minmax(values: List[float]) -> List[float]:
    if not values:
        return []
    lo, hi = min(values), max(values)
    if hi - lo < 1e-9:
        return [1.0 for _ in values]
    return [(v - lo) / (hi - lo) for v in values]


class HybridRetriever:
    def __init__(self) -> None:
        self._bm25: Optional[BM25Retriever] = None
        self._vec: Optional[VectorRetriever] = None

    def _bm25_lazy(self) -> BM25Retriever:
        if self._bm25 is None:
            self._bm25 = BM25Retriever()
        return self._bm25

    def _vec_lazy(self) -> Optional[VectorRetriever]:
        if self._vec is None:
            try:
                self._vec = VectorRetriever()
            except Exception:
                self._vec = None
        return self._vec

    def refresh(self) -> None:
        self._bm25 = BM25Retriever()
        try:
            self._vec = VectorRetriever()
        except Exception:
            self._vec = None

    def search(self, query: str, k: Optional[int] = None,
               trust_boost: bool = True) -> List[Tuple[dict, float]]:
        s = get_settings()
        k = k or s.top_k

        # Always refresh BM25 so newly-ingested chunks are visible in the
        # short-lived API/CLI processes typical of a research prototype.
        self._bm25 = BM25Retriever()
        bm = self._bm25.search(query, k=max(k * 2, 8))
        vec = []
        v = self._vec_lazy()
        if v is not None:
            vec = v.search(query, k=max(k * 2, 8))

        merged: dict[str, dict] = {}
        bm_scores = _minmax([sc for _, sc in bm])
        for (chunk, _), nsc in zip(bm, bm_scores):
            merged[chunk["chunk_id"]] = {"chunk": chunk, "bm": nsc, "vec": 0.0}

        vec_scores = _minmax([sc for _, sc in vec])
        for (chunk, _), nsc in zip(vec, vec_scores):
            entry = merged.setdefault(chunk["chunk_id"], {"chunk": chunk, "bm": 0.0, "vec": 0.0})
            entry["vec"] = nsc

        alpha = s.hybrid_alpha
        results: List[Tuple[dict, float]] = []
        for cid, entry in merged.items():
            score = alpha * entry["vec"] + (1 - alpha) * entry["bm"]
            if trust_boost:
                doc = get_document(entry["chunk"].get("doc_id") or "")
                trust = (doc or {}).get("trust_score") or s.default_trust_score
                score *= 0.5 + 0.5 * float(trust)
            results.append((entry["chunk"], score))

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:k]
