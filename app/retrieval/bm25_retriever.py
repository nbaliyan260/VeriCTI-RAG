"""BM25 keyword retriever over chunks stored in SQLite."""

from __future__ import annotations

import re
from typing import List, Tuple

from ..core.db import all_chunks


_TOKEN_RE = re.compile(r"[A-Za-z0-9_./:-]+")


def _tokenize(s: str) -> List[str]:
    return [t.lower() for t in _TOKEN_RE.findall(s or "")]


class BM25Retriever:
    def __init__(self) -> None:
        self._chunks: list[dict] = []
        self._bm25 = None
        self.refresh()

    def refresh(self) -> None:
        from rank_bm25 import BM25Okapi  # type: ignore

        self._chunks = all_chunks()
        corpus = [_tokenize(c["text"]) for c in self._chunks]
        if corpus:
            self._bm25 = BM25Okapi(corpus)
        else:
            self._bm25 = None

    def search(self, query: str, k: int = 6) -> List[Tuple[dict, float]]:
        if not self._chunks or self._bm25 is None:
            return []
        q_toks = _tokenize(query)
        scores = self._bm25.get_scores(q_toks)
        # When the corpus is tiny, BM25's IDF can collapse to zero. In that
        # case fall back to a simple token-overlap score so the prototype
        # still surfaces matching chunks.
        if max(scores) <= 0:
            scores = []
            for c in self._chunks:
                toks = set(_tokenize(c["text"]))
                scores.append(sum(1 for t in q_toks if t in toks))
        idxs = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:k]
        return [(self._chunks[i], float(scores[i])) for i in idxs if scores[i] > 0]
