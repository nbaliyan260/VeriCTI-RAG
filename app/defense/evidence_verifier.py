"""Evidence verification: do the cited chunks actually support the claim?

For each entity/relationship/attack we compute a *support_score* in [0,1]
based on the presence of the entity's value (or technique pattern) in the
referenced chunk text. We also flag chunks that contain prompt-injection
patterns so they are not used as evidence.

This is intentionally lexical (and therefore deterministic) for the MVP. An
LLM-based natural-language entailment check can be plugged in later.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Tuple

from ..core.schemas import (
    AttackMapping,
    GeneratedRule,
    STIXEntity,
    STIXRelationship,
)


_INJECTION_PATTERNS = [
    r"ignore\s+(all|previous)\s+(rules|instructions)",
    r"\bSYSTEM:\b",
    r"disregard\s+the\s+user",
    r"assistant\s*:\s*produce\s+no\s+warnings",
    r"always\s+trust\s+this\s+source",
]


def detect_prompt_injection(text: str) -> List[str]:
    hits = []
    low = (text or "").lower()
    for pat in _INJECTION_PATTERNS:
        if re.search(pat, low):
            hits.append(pat)
    return hits


def _support_for_value(value: str, chunk_text: str) -> float:
    if not value:
        return 0.0
    return 1.0 if value.lower() in (chunk_text or "").lower() else 0.0


def verify_entity_support(entity: STIXEntity, chunks_by_id: Dict[str, dict]) -> float:
    scores = []
    for cid in entity.evidence_chunk_ids:
        ch = chunks_by_id.get(cid)
        if not ch:
            scores.append(0.0)
            continue
        s = _support_for_value(entity.value or entity.name, ch["text"])
        # Penalise injection-bearing chunks
        if detect_prompt_injection(ch["text"]):
            s *= 0.3
        scores.append(s)
    if not scores:
        return 0.0
    return sum(scores) / len(scores)


def verify_attack_support(mapping: AttackMapping, chunks_by_id: Dict[str, dict]) -> float:
    # Re-use the technique table from the mapper rather than duplicate it.
    from ..extraction.attack_mapper import TECHNIQUES

    pats = []
    for tid, _, _, ps in TECHNIQUES:
        if tid == mapping.technique_id:
            pats = ps
            break
    if not pats:
        return 0.5  # unknown technique => neutral
    scores = []
    for cid in mapping.evidence_chunk_ids:
        ch = chunks_by_id.get(cid)
        if not ch:
            scores.append(0.0)
            continue
        text_low = ch["text"].lower()
        hits = sum(1 for p in pats if re.search(p, text_low))
        s = min(1.0, hits / max(1, len(pats)) + (0.3 if hits else 0.0))
        if detect_prompt_injection(ch["text"]):
            s *= 0.3
        scores.append(s)
    return sum(scores) / len(scores) if scores else 0.0


def verify_rule_support(rule: GeneratedRule, chunks_by_id: Dict[str, dict]) -> Tuple[bool, float]:
    """Returns (semantic_valid, support_score)."""
    if not rule.evidence_chunk_ids:
        return False, 0.0
    # Map technique back to the same lexical evidence used for the mapping.
    fake = AttackMapping(
        technique_id=rule.attack_technique or "T0000",
        technique_name="auto", tactic="auto",
        evidence_chunk_ids=rule.evidence_chunk_ids,
        confidence=rule.confidence,
    )
    support = verify_attack_support(fake, chunks_by_id)
    return support >= 0.4, support


def verify_relationship_support(rel: STIXRelationship,
                                chunks_by_id: Dict[str, dict]) -> float:
    scores = []
    for cid in rel.evidence_chunk_ids:
        ch = chunks_by_id.get(cid)
        if not ch:
            scores.append(0.0)
            continue
        text_low = ch["text"].lower()
        if rel.relationship_type.lower() in text_low or \
                rel.relationship_type.replace("-", " ") in text_low:
            scores.append(0.8)
        else:
            scores.append(0.4)
        if detect_prompt_injection(ch["text"]):
            scores[-1] *= 0.3
    return sum(scores) / len(scores) if scores else 0.0
