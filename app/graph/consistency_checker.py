"""Graph-based consistency checks for the evidence graph."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

import networkx as nx


def _entity_support_count(g: nx.MultiDiGraph, node: str) -> int:
    """Count distinct documents that support an entity via chunk edges."""
    docs = set()
    for u, _, data in g.in_edges(node, data=True):
        if data.get("rel") != "supports":
            continue
        if g.nodes[u].get("kind") != "chunk":
            continue
        doc_id = g.nodes[u].get("doc_id")
        if doc_id:
            docs.add(doc_id)
    return len(docs)


def check_consistency(g: nx.MultiDiGraph) -> Dict[str, List[str]]:
    """Return a dict of warning categories => list of human-readable messages."""
    warnings: Dict[str, List[str]] = defaultdict(list)

    # 1. Entities supported by a single source
    for n, attrs in g.nodes(data=True):
        if attrs.get("kind") != "entity":
            continue
        if _entity_support_count(g, n) <= 1:
            warnings["single_source"].append(
                f"Entity {attrs.get('name', n)} supported by only one document"
            )

    # 2. Entities with no evidence at all
    for n, attrs in g.nodes(data=True):
        if attrs.get("kind") != "entity":
            continue
        has_evidence = any(
            data.get("rel") == "supports" and g.nodes[u].get("kind") == "chunk"
            for u, _, data in g.in_edges(n, data=True)
        )
        if not has_evidence:
            warnings["unsupported_entity"].append(
                f"Entity {attrs.get('name', n)} has no chunk evidence"
            )

    # 3. Contradictory `attributed-to` edges: same source entity attributed
    #    to multiple distinct threat actors.
    attribution: Dict[str, set] = defaultdict(set)
    for u, v, data in g.edges(data=True):
        if data.get("rel") == "attributed-to":
            attribution[u].add(v)
    for src, targets in attribution.items():
        if len(targets) > 1:
            warnings["contradictory_attribution"].append(
                f"Entity {src} attributed to multiple actors: {sorted(targets)}"
            )

    # 4. Rules detecting an attack technique that has no chunk evidence
    for n, attrs in g.nodes(data=True):
        if attrs.get("kind") != "rule":
            continue
        attack = attrs.get("attack")
        if not attack:
            warnings["rule_missing_attack"].append(f"Rule {n} has no ATT&CK tag")
            continue
        if attack in g and not any(
            data.get("rel") == "supports" and g.nodes[u].get("kind") == "chunk"
            for u, _, data in g.in_edges(attack, data=True)
        ):
            warnings["rule_attack_unsupported"].append(
                f"Rule {n} maps to {attack} but technique has no chunk evidence"
            )
    return dict(warnings)
