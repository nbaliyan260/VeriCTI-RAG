"""Builds the CTI evidence graph used by the verification layer.

Nodes:
    document, chunk, entity (STIX), attack (technique), rule
Edges:
    document --contains--> chunk
    chunk --supports--> entity / attack / rule
    entity --rel(type)--> entity
    rule --detects--> attack
"""

from __future__ import annotations

from typing import Iterable, List

import networkx as nx

from ..core.schemas import (
    AttackMapping,
    GeneratedRule,
    STIXEntity,
    STIXRelationship,
)


def build_graph(
    *,
    documents: Iterable[dict],
    chunks: Iterable[dict],
    entities: Iterable[STIXEntity],
    relationships: Iterable[STIXRelationship],
    attack_mappings: Iterable[AttackMapping] = (),
    rules: Iterable[GeneratedRule] = (),
) -> nx.MultiDiGraph:
    g = nx.MultiDiGraph()

    for d in documents:
        g.add_node(d["doc_id"], kind="document", **{k: v for k, v in d.items() if k != "doc_id"})

    for c in chunks:
        g.add_node(c["chunk_id"], kind="chunk",
                   doc_id=c.get("doc_id"),
                   start_char=c.get("start_char"),
                   end_char=c.get("end_char"))
        if c.get("doc_id"):
            g.add_edge(c["doc_id"], c["chunk_id"], rel="contains")

    for e in entities:
        g.add_node(e.entity_id, kind="entity", stix_type=e.stix_type,
                   name=e.name, value=e.value, confidence=e.confidence)
        for cid in e.evidence_chunk_ids:
            if cid in g:
                g.add_edge(cid, e.entity_id, rel="supports")

    for r in relationships:
        g.add_edge(r.source_entity, r.target_entity, rel=r.relationship_type,
                   relationship_id=r.relationship_id,
                   evidence_chunk_ids=list(r.evidence_chunk_ids),
                   confidence=r.confidence)

    for m in attack_mappings:
        g.add_node(m.technique_id, kind="attack", technique_name=m.technique_name,
                   tactic=m.tactic, confidence=m.confidence)
        for cid in m.evidence_chunk_ids:
            if cid in g:
                g.add_edge(cid, m.technique_id, rel="supports")

    for r in rules:
        g.add_node(r.rule_id, kind="rule", title=r.title,
                   attack=r.attack_technique, confidence=r.confidence)
        for cid in r.evidence_chunk_ids:
            if cid in g:
                g.add_edge(cid, r.rule_id, rel="supports")
        if r.attack_technique:
            g.add_edge(r.rule_id, r.attack_technique, rel="detects")

    return g


def graph_to_dict(g: nx.MultiDiGraph) -> dict:
    return {
        "nodes": [{"id": n, **g.nodes[n]} for n in g.nodes()],
        "edges": [
            {"source": u, "target": v, **data}
            for u, v, data in g.edges(data=True)
        ],
    }
