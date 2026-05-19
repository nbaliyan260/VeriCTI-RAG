"""Vector retriever using ChromaDB with a sentence-transformer embedder.

Falls back to a deterministic hash-bag embedder when sentence-transformers is
unavailable (CI / sandboxed test environments).
"""

from __future__ import annotations

import hashlib
from typing import List, Tuple

from ..core.config import get_settings


def _hash_embed(text: str, dim: int = 384) -> List[float]:
    vec = [0.0] * dim
    for tok in text.lower().split():
        h = int(hashlib.md5(tok.encode()).hexdigest(), 16)
        vec[h % dim] += 1.0
    norm = sum(x * x for x in vec) ** 0.5 or 1.0
    return [x / norm for x in vec]


class _EmbedderShim:
    """Tiny shim so Chroma can call ``__call__`` without sentence-transformers."""

    def __init__(self) -> None:
        self._st = None
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore

            self._st = SentenceTransformer(get_settings().embedding_model)
        except Exception:
            self._st = None

    def __call__(self, input):  # noqa: A002 - chroma signature
        if isinstance(input, str):
            input = [input]
        if self._st is not None:
            return self._st.encode(list(input), normalize_embeddings=True).tolist()
        return [_hash_embed(t) for t in input]

    # New Chroma API
    def name(self) -> str:
        return "vericti-embedder"


class VectorRetriever:
    COLLECTION = "vericti_chunks"

    def __init__(self) -> None:
        import chromadb  # type: ignore

        self._client = chromadb.PersistentClient(path=str(get_settings().chroma_dir))
        self._embedder = _EmbedderShim()
        self._collection = self._client.get_or_create_collection(
            self.COLLECTION, embedding_function=self._embedder
        )

    def add(self, chunks: List[dict]) -> None:
        if not chunks:
            return
        ids = [c["chunk_id"] for c in chunks]
        docs = [c["text"] for c in chunks]
        metas = [
            {"doc_id": c["doc_id"], "start_char": c["start_char"], "end_char": c["end_char"]}
            for c in chunks
        ]
        # Upsert
        try:
            self._collection.upsert(ids=ids, documents=docs, metadatas=metas)
        except Exception:
            # Older chroma versions
            self._collection.add(ids=ids, documents=docs, metadatas=metas)

    def search(self, query: str, k: int = 6) -> List[Tuple[dict, float]]:
        try:
            res = self._collection.query(query_texts=[query], n_results=k)
        except Exception:
            return []
        out: List[Tuple[dict, float]] = []
        ids = (res.get("ids") or [[]])[0]
        docs = (res.get("documents") or [[]])[0]
        metas = (res.get("metadatas") or [[]])[0]
        dists = (res.get("distances") or [[0.0] * len(ids)])[0]
        for cid, text, meta, dist in zip(ids, docs, metas, dists):
            score = 1.0 / (1.0 + float(dist))  # convert distance to similarity
            chunk = {
                "chunk_id": cid,
                "doc_id": meta.get("doc_id"),
                "text": text,
                "start_char": meta.get("start_char", 0),
                "end_char": meta.get("end_char", 0),
                "metadata": meta,
            }
            out.append((chunk, score))
        return out
