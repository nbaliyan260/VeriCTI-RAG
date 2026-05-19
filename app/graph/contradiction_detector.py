"""Cross-source contradiction detector.

For the MVP we focus on two contradictions:

1. Same malware family attributed to different threat actors across reports.
2. Same IOC marked benign in one chunk and malicious in another.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

import networkx as nx


_BENIGN_WORDS = {"benign", "legitimate", "false positive", "not malicious"}


def detect_contradictions(g: nx.MultiDiGraph, chunks_by_id: Dict[str, dict]) -> List[str]:
    out: List[str] = []

    # 1. Multi-actor attribution (same malware -> different actors)
    by_malware: Dict[str, set] = defaultdict(set)
    for u, v, data in g.edges(data=True):
        if data.get("rel") != "attributed-to":
            continue
        if g.nodes.get(u, {}).get("stix_type") == "malware":
            by_malware[u].add(v)
    for mw, actors in by_malware.items():
        if len(actors) > 1:
            out.append(f"Contradictory attribution for malware {mw}: {sorted(actors)}")

    # 2. IOC mentioned as benign in some chunks but malicious in others
    for n, attrs in g.nodes(data=True):
        if attrs.get("stix_type") != "indicator":
            continue
        chunks = [
            u for u, _, data in g.in_edges(n, data=True)
            if data.get("rel") == "supports"
        ]
        benign = malicious = False
        for cid in chunks:
            text = (chunks_by_id.get(cid) or {}).get("text", "").lower()
            if any(w in text for w in _BENIGN_WORDS):
                benign = True
            if "malicious" in text or "c2" in text or "payload" in text:
                malicious = True
        if benign and malicious:
            out.append(f"IOC {attrs.get('value', n)} described as both benign and malicious")
    return out
