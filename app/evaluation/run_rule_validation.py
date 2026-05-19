"""Run Sigma rule validation across all rules of a document."""

from __future__ import annotations

from typing import Dict, List

from ..core.db import get_chunks
from ..services import pipeline as svc


def validate_all_rules_for_doc(doc_id: str) -> Dict:
    rules = svc.generate_rules_for_doc(doc_id)
    chunks_by_id = {c["chunk_id"]: c for c in get_chunks(doc_id)}
    results = [svc.verify_rule(r, chunks_by_id).model_dump() for r in rules]
    n_verified = sum(1 for r in results if r["final_verdict"] == "verified")
    return {
        "doc_id": doc_id,
        "n_rules": len(rules),
        "n_verified": n_verified,
        "results": results,
        "rules": [r.model_dump() for r in rules],
    }
