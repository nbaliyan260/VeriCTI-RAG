"""Provenance checker.

Verifies that every entity, relationship, ATT&CK mapping, and rule has at
least one evidence chunk and that the referenced chunks actually exist
in the chunk store.
"""

from __future__ import annotations

from typing import Dict, Iterable, List

from ..core.schemas import (
    AttackMapping,
    GeneratedRule,
    STIXEntity,
    STIXRelationship,
)


def _check(item, chunk_ids: set, kind: str) -> List[str]:
    issues = []
    if not item.evidence_chunk_ids:
        issues.append(f"{kind} {getattr(item, 'name', '')} has no evidence")
    for cid in item.evidence_chunk_ids:
        if cid not in chunk_ids:
            issues.append(f"{kind} references unknown chunk {cid}")
    return issues


def check_provenance(
    *,
    chunks: Iterable[Dict],
    entities: Iterable[STIXEntity] = (),
    relationships: Iterable[STIXRelationship] = (),
    attack_mappings: Iterable[AttackMapping] = (),
    rules: Iterable[GeneratedRule] = (),
) -> Dict[str, List[str]]:
    chunk_ids = {c["chunk_id"] for c in chunks}
    issues: Dict[str, List[str]] = {
        "entity": [], "relationship": [], "attack": [], "rule": []
    }
    for e in entities:
        issues["entity"] += _check(e, chunk_ids, "entity")
    for r in relationships:
        issues["relationship"] += _check(r, chunk_ids, "relationship")
    for a in attack_mappings:
        issues["attack"] += _check(a, chunk_ids, "attack")
    for ru in rules:
        issues["rule"] += _check(ru, chunk_ids, "rule")
    return issues
