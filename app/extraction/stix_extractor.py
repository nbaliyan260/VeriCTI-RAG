"""STIX entity + relationship extraction.

The MVP uses a deterministic hybrid:

1. Regex IOC extraction emits `indicator` entities (see ``ioc_extractor``).
2. A small CTI gazetteer matches known malware families, threat actors,
   and tools mentioned in the chunk text.
3. Relationships are produced when two entities co-occur in the same chunk
   under a verb pattern (e.g. ``uses``, ``drops``, ``attributed to``).

This guarantees deterministic output, full evidence links, and no LLM
dependency for the MVP. When an LLM is configured, the rule-based output
can be augmented by ``llm_postprocess`` (not in MVP).
"""

from __future__ import annotations

import hashlib
import re
from typing import Dict, Iterable, List, Tuple

from ..core.schemas import STIXEntity, STIXRelationship
from .ioc_extractor import extract_iocs


# Tiny built-in gazetteer. Extend via prompts/ or external file later.
MALWARE_FAMILIES = {
    "examplerat", "emotet", "trickbot", "qakbot", "cobaltstrike", "cobalt strike",
    "mimikatz", "ryuk", "lockbit", "conti", "agenttesla", "redline",
    "icedid", "bumblebee", "njrat", "remcos", "raspberryrobin",
}

THREAT_ACTORS = {
    "apt28", "apt29", "fin7", "fin8", "lazarus", "carbanak", "ta505",
    "muddywater", "kimsuky", "turla", "wizard spider", "scattered spider",
}

TOOLS = {
    "powershell", "cmd.exe", "rundll32", "regsvr32", "certutil", "wscript",
    "mshta", "psexec", "wmic", "bitsadmin",
}

_REL_PATTERNS: List[Tuple[str, str]] = [
    (r"\buses?\b|\bleverag(?:es|ed|ing)\b|\bemploys?\b", "uses"),
    (r"\bdrops?\b|\bdownloads?\b|\bdelivers?\b|\binstalls?\b", "drops"),
    (r"\bcommunicates? with\b|\bbeacons? to\b|\bconnects? to\b|\bc2\b", "communicates-with"),
    (r"\battributed to\b|\bassociated with\b|\blinked to\b", "attributed-to"),
    (r"\bexploits?\b|\bleverages?\b|\babuses?\b", "exploits"),
]


def _entity_id(stix_type: str, name: str) -> str:
    h = hashlib.sha1(f"{stix_type}:{name.lower()}".encode()).hexdigest()[:10]
    return f"{stix_type}_{h}"


def _find_gazetteer_entities(chunk: Dict) -> List[STIXEntity]:
    text = chunk["text"]
    low = text.lower()
    out: List[STIXEntity] = []
    for term in MALWARE_FAMILIES:
        if term in low:
            out.append(STIXEntity(
                entity_id=_entity_id("malware", term),
                stix_type="malware", name=term.title(), value=term,
                confidence=0.7, evidence_chunk_ids=[chunk["chunk_id"]],
            ))
    for term in THREAT_ACTORS:
        if term in low:
            out.append(STIXEntity(
                entity_id=_entity_id("threat-actor", term),
                stix_type="threat-actor", name=term.upper(), value=term,
                confidence=0.7, evidence_chunk_ids=[chunk["chunk_id"]],
            ))
    for term in TOOLS:
        if term in low:
            out.append(STIXEntity(
                entity_id=_entity_id("tool", term),
                stix_type="tool", name=term, value=term,
                confidence=0.7, evidence_chunk_ids=[chunk["chunk_id"]],
            ))
    return out


def _dedupe_entities(entities: Iterable[STIXEntity]) -> List[STIXEntity]:
    by_id: Dict[str, STIXEntity] = {}
    for e in entities:
        if e.entity_id in by_id:
            existing = by_id[e.entity_id]
            existing.evidence_chunk_ids = sorted(set(
                existing.evidence_chunk_ids + e.evidence_chunk_ids))
            existing.confidence = min(0.99, existing.confidence + 0.05)
        else:
            by_id[e.entity_id] = e
    return list(by_id.values())


def extract_stix(chunks: List[Dict]) -> Tuple[List[STIXEntity], List[STIXRelationship]]:
    entities: List[STIXEntity] = []

    # 1. IOCs as STIX indicators
    entities.extend(extract_iocs(chunks))

    # 2. Gazetteer matches per chunk
    for ch in chunks:
        entities.extend(_find_gazetteer_entities(ch))

    entities = _dedupe_entities(entities)

    # 3. Relationships from co-occurrence + verb patterns within a chunk
    relationships: List[STIXRelationship] = []
    seen_rels: set[str] = set()
    for ch in chunks:
        text = ch["text"]
        low = text.lower()
        chunk_ents = [e for e in entities if ch["chunk_id"] in e.evidence_chunk_ids]
        for e1 in chunk_ents:
            for e2 in chunk_ents:
                if e1.entity_id == e2.entity_id:
                    continue
                name1 = (e1.value or e1.name).lower()
                name2 = (e2.value or e2.name).lower()
                if name1 not in low or name2 not in low:
                    continue
                # Look for a verb pattern between the two mentions
                pos1 = low.find(name1)
                pos2 = low.find(name2)
                if pos1 < 0 or pos2 < 0 or pos1 == pos2:
                    continue
                lo, hi = sorted([pos1, pos2])
                between = low[lo:hi + 80]
                rel_type = None
                for pat, rname in _REL_PATTERNS:
                    if re.search(pat, between):
                        rel_type = rname
                        break
                if not rel_type:
                    continue
                rel_id = hashlib.sha1(
                    f"{e1.entity_id}->{rel_type}->{e2.entity_id}".encode()
                ).hexdigest()[:12]
                if rel_id in seen_rels:
                    continue
                seen_rels.add(rel_id)
                relationships.append(
                    STIXRelationship(
                        relationship_id=f"rel_{rel_id}",
                        source_entity=e1.entity_id,
                        relationship_type=rel_type,
                        target_entity=e2.entity_id,
                        confidence=0.65,
                        evidence_chunk_ids=[ch["chunk_id"]],
                    )
                )
    return entities, relationships
