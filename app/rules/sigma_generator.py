"""Generate Sigma rules from extracted ATT&CK mappings + chunk evidence.

The generator is template-driven. Each supported ATT&CK technique has a
``SigmaTemplate`` describing the logsource and selection block. The generator
fills in the references / tags / evidence and yields a ``GeneratedRule``.

This keeps the MVP deterministic, evidence-faithful, and offline. An LLM
adapter can be added later for free-form techniques.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import date
from typing import Dict, List, Optional

import yaml

from ..core.schemas import AttackMapping, GeneratedRule


@dataclass
class SigmaTemplate:
    title: str
    description: str
    logsource: Dict[str, str]
    selection: Dict[str, object]
    condition: str = "selection"
    level: str = "high"
    tags: List[str] = field(default_factory=list)


TEMPLATES: Dict[str, SigmaTemplate] = {
    "T1059.001": SigmaTemplate(
        title="Suspicious Encoded PowerShell Execution",
        description=("Detects encoded or base64 PowerShell command execution "
                     "as described in CTI report."),
        logsource={"product": "windows", "category": "process_creation"},
        selection={
            "Image|endswith": "\\powershell.exe",
            "CommandLine|contains": ["-enc", "-encodedcommand", "FromBase64String"],
        },
        tags=["attack.execution", "attack.t1059.001"],
    ),
    "T1059.003": SigmaTemplate(
        title="Suspicious Command Shell Execution",
        description="Detects suspicious cmd.exe usage referenced in CTI.",
        logsource={"product": "windows", "category": "process_creation"},
        selection={
            "Image|endswith": "\\cmd.exe",
            "CommandLine|contains": ["/c ", "&", "|"],
        },
        tags=["attack.execution", "attack.t1059.003"],
    ),
    "T1218.011": SigmaTemplate(
        title="Suspicious Rundll32 Execution",
        description="Detects rundll32.exe usage indicative of proxy execution.",
        logsource={"product": "windows", "category": "process_creation"},
        selection={
            "Image|endswith": "\\rundll32.exe",
            "CommandLine|contains": [",", ".dll"],
        },
        tags=["attack.defense_evasion", "attack.t1218.011"],
    ),
    "T1218.010": SigmaTemplate(
        title="Suspicious Regsvr32 Execution",
        description="Detects regsvr32 squiblydoo-style execution.",
        logsource={"product": "windows", "category": "process_creation"},
        selection={
            "Image|endswith": "\\regsvr32.exe",
            "CommandLine|contains": ["/s", "/u", "/i:"],
        },
        tags=["attack.defense_evasion", "attack.t1218.010"],
    ),
    "T1105": SigmaTemplate(
        title="Ingress Tool Transfer via LOLBins",
        description="Detects certutil/bitsadmin used for file download.",
        logsource={"product": "windows", "category": "process_creation"},
        selection={
            "Image|endswith": ["\\certutil.exe", "\\bitsadmin.exe"],
            "CommandLine|contains": ["urlcache", "transfer", "http"],
        },
        tags=["attack.command_and_control", "attack.t1105"],
    ),
    "T1047": SigmaTemplate(
        title="Suspicious WMI Process Creation",
        description="Detects WMI-based process creation (wmic / Win32_Process).",
        logsource={"product": "windows", "category": "process_creation"},
        selection={
            "Image|endswith": "\\wmic.exe",
            "CommandLine|contains": ["process call create", "Win32_Process"],
        },
        tags=["attack.execution", "attack.t1047"],
    ),
}


def _rule_id(doc_id: str, technique_id: str) -> str:
    h = hashlib.sha1(f"{doc_id}:{technique_id}".encode()).hexdigest()[:10]
    return f"vericti-{technique_id.lower()}-{h}"


def render_sigma(template: SigmaTemplate, *, rule_id: str,
                 evidence_chunk_ids: List[str]) -> str:
    payload = {
        "title": template.title,
        "id": rule_id,
        "status": "experimental",
        "description": template.description,
        "references": [f"evidence:{cid}" for cid in evidence_chunk_ids],
        "author": "VeriCTI-RAG",
        "date": date.today().isoformat(),
        "tags": template.tags,
        "logsource": template.logsource,
        "detection": {
            "selection": template.selection,
            "condition": template.condition,
        },
        "level": template.level,
    }
    return yaml.safe_dump(payload, sort_keys=False)


def generate_rules(doc_id: str, attack_mappings: List[AttackMapping]) -> List[GeneratedRule]:
    out: List[GeneratedRule] = []
    for m in attack_mappings:
        tmpl = TEMPLATES.get(m.technique_id)
        if tmpl is None:
            continue
        rid = _rule_id(doc_id, m.technique_id)
        rule_text = render_sigma(tmpl, rule_id=rid, evidence_chunk_ids=m.evidence_chunk_ids)
        out.append(
            GeneratedRule(
                rule_id=rid,
                rule_type="sigma",
                title=tmpl.title,
                rule_text=rule_text,
                attack_technique=m.technique_id,
                evidence_chunk_ids=list(m.evidence_chunk_ids),
                confidence=min(0.95, 0.6 + 0.1 * len(m.evidence_chunk_ids)),
            )
        )
    return out


def supported_techniques() -> List[str]:
    return sorted(TEMPLATES.keys())
