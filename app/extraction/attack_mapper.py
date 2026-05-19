"""Simple keyword-driven MITRE ATT&CK mapper with evidence links.

The mapping table is intentionally small and conservative. It supports the
behaviors that the MVP Sigma generator can also produce rules for, so the
evidence/rule chain is end-to-end testable without an LLM.
"""

from __future__ import annotations

import re
from typing import Dict, List

from ..core.schemas import AttackMapping


# (technique_id, technique_name, tactic, patterns)
TECHNIQUES = [
    ("T1059.001", "PowerShell", "Execution",
     [r"powershell", r"-enc(?:odedcommand)?", r"frombase64string"]),
    ("T1059.003", "Windows Command Shell", "Execution",
     [r"\bcmd\.exe\b", r"\bcommand prompt\b"]),
    ("T1218.011", "Rundll32", "Defense Evasion",
     [r"\brundll32\b"]),
    ("T1218.010", "Regsvr32", "Defense Evasion",
     [r"\bregsvr32\b"]),
    ("T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion",
     [r"\bbase64\b", r"\bdeobfuscat", r"\bdecode"]),
    ("T1071.001", "Application Layer Protocol: Web", "Command and Control",
     [r"\bc2\b", r"\bcommand and control\b", r"\bbeacon", r"https?://"]),
    ("T1105", "Ingress Tool Transfer", "Command and Control",
     [r"\bdownloads?\b", r"\bcertutil\b", r"\bbitsadmin\b"]),
    ("T1047", "Windows Management Instrumentation", "Execution",
     [r"\bwmi\b", r"\bwmic\b", r"\bwin32_process\b"]),
    ("T1003", "OS Credential Dumping", "Credential Access",
     [r"\bmimikatz\b", r"\blsass\b", r"\bcredential dump"]),
    ("T1486", "Data Encrypted for Impact", "Impact",
     [r"\bransomware\b", r"\bencrypt(?:s|ed|ing)? files\b"]),
    ("T1566.001", "Spearphishing Attachment", "Initial Access",
     [r"\bphishing email\b", r"\bmalicious attachment\b", r"\bweaponi[sz]ed document\b"]),
]


def map_attack(chunks: List[Dict]) -> List[AttackMapping]:
    out: Dict[str, AttackMapping] = {}
    for ch in chunks:
        text_low = ch["text"].lower()
        for tid, tname, tactic, patterns in TECHNIQUES:
            hits = sum(1 for p in patterns if re.search(p, text_low))
            if hits == 0:
                continue
            base_conf = min(0.95, 0.55 + 0.1 * hits)
            if tid in out:
                m = out[tid]
                m.evidence_chunk_ids = sorted(set(m.evidence_chunk_ids + [ch["chunk_id"]]))
                m.confidence = min(0.99, m.confidence + 0.05)
            else:
                out[tid] = AttackMapping(
                    technique_id=tid,
                    technique_name=tname,
                    tactic=tactic,
                    confidence=base_conf,
                    evidence_chunk_ids=[ch["chunk_id"]],
                )
    return list(out.values())
