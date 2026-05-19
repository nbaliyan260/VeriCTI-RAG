"""Compare extraction on clean vs poisoned variants of a report.

This is the script that the ``/evaluate`` endpoint and the demo invoke. It
returns a small JSON-serialisable dict; the Streamlit UI renders it.
"""

from __future__ import annotations

import re
from typing import Dict, List

from ..services import pipeline as svc
from .metrics import (
    attack_mapping_accuracy,
    evidence_faithfulness,
    poisoning_success_rate,
)


def _ioc_values(entities: List[dict]) -> List[str]:
    return [e["value"] for e in entities if e.get("stix_type") == "indicator" and e.get("value")]


def _technique_ids(mappings: List[dict]) -> List[str]:
    return [m["technique_id"] for m in mappings]


def compare_clean_vs_poisoned(clean_doc_id: str, poisoned_doc_id: str) -> Dict:
    clean = svc.extract_for_doc(clean_doc_id)
    poisoned = svc.extract_for_doc(poisoned_doc_id)

    def _supported_indicator_values(payload: Dict) -> set[str]:
        vals: set[str] = set()
        for e in payload["entities"]:
            if e.get("stix_type") != "indicator":
                continue
            v = e.get("value")
            if not v:
                continue
            # Only count indicators with explicit evidence.
            ev = e.get("evidence_chunk_ids") or []
            if not ev:
                continue
            vals.add(v)
        return vals

    clean_iocs = _supported_indicator_values(clean)
    poisoned_iocs = _supported_indicator_values(poisoned)

    newly_introduced = sorted(poisoned_iocs - clean_iocs)

    # Defensive post-filter: only keep IOCs that appear as whole tokens in the
    # poisoned text. This prevents substring artifacts (e.g. "xample-c2.com")
    # from being treated as successful poisoning.
    chunk_texts = [ch.get("text", "") for ch in poisoned.get("chunks", [])]
    combined_text = "\n".join(chunk_texts)

    def _has_whole_token(val: str) -> bool:
        if not val:
            return False
        # Also consider a defanged variant for domains.
        candidates = [val]
        if "." in val and "[.]" not in val:
            candidates.append(val.replace(".", "[.]") )
        # For domains/URLs/hashes, allow punctuation adjacency but avoid
        # mid-token matches (e.g. "...example-c2.com" -> "xample-c2.com").
        for cand in candidates:
            if any(ch in cand for ch in ".:/"):
                pat = rf"(?<![A-Za-z0-9]){re.escape(cand)}(?![A-Za-z0-9])"
            else:
                pat = rf"(?<![A-Za-z0-9-]){re.escape(cand)}(?![A-Za-z0-9-])"
            if re.search(pat, combined_text) is not None:
                return True
        return False

    def _appears_in_any_chunk(val: str) -> bool:
        # Require the refanged value to appear verbatim in at least one chunk.
        return any(val in t for t in chunk_texts)

    newly_introduced = [
        v for v in newly_introduced
        if _has_whole_token(v) and _appears_in_any_chunk(v)
    ]

    clean_tech = _technique_ids(clean["attack_mappings"])
    poisoned_tech = _technique_ids(poisoned["attack_mappings"])

    return {
        "clean_doc_id": clean_doc_id,
        "poisoned_doc_id": poisoned_doc_id,
        "n_clean_entities": len(clean["entities"]),
        "n_poisoned_entities": len(poisoned["entities"]),
        "newly_introduced_iocs": newly_introduced,
        "attack_mapping_overlap": attack_mapping_accuracy(poisoned_tech, clean_tech),
        "evidence_faithfulness_clean": evidence_faithfulness(
            [type("E", (), e) for e in clean["entities"]]
        ),
        "evidence_faithfulness_poisoned": evidence_faithfulness(
            [type("E", (), e) for e in poisoned["entities"]]
        ),
        "poisoning_success_rate_estimate": poisoning_success_rate(
            poisoned_iocs, newly_introduced
        ),
    }
