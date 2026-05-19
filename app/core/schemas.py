"""Pydantic data models used across the VeriCTI-RAG pipeline.

Every model carries the evidence-link fields that the verification layer
relies on. The cardinal rule of the system is enforced here:

> No entity, relationship, ATT&CK mapping, or rule is acceptable without
> at least one `evidence_chunk_id`.

Downstream code that violates this invariant should raise.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Document & chunk
# ---------------------------------------------------------------------------


class Document(BaseModel):
    doc_id: str
    title: str
    source: str = "unknown"
    source_type: str = "unknown"  # vendor_blog | government | academic | unknown
    published_date: Optional[str] = None
    ingested_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    trust_score: float = 0.6
    file_path: Optional[str] = None


class Chunk(BaseModel):
    chunk_id: str
    doc_id: str
    text: str
    start_char: int
    end_char: int
    metadata: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# STIX-style outputs
# ---------------------------------------------------------------------------


class STIXEntity(BaseModel):
    entity_id: str
    stix_type: str  # indicator | malware | threat-actor | attack-pattern | tool ...
    name: str
    value: Optional[str] = None
    confidence: float = 0.0
    evidence_chunk_ids: List[str] = Field(default_factory=list)

    @field_validator("evidence_chunk_ids")
    @classmethod
    def _require_evidence(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("STIXEntity must have >=1 evidence_chunk_ids")
        return v


class STIXRelationship(BaseModel):
    relationship_id: str
    source_entity: str
    relationship_type: str
    target_entity: str
    confidence: float = 0.0
    evidence_chunk_ids: List[str] = Field(default_factory=list)

    @field_validator("evidence_chunk_ids")
    @classmethod
    def _require_evidence(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("STIXRelationship must have >=1 evidence_chunk_ids")
        return v


class AttackMapping(BaseModel):
    technique_id: str  # e.g. T1059.001
    technique_name: str
    tactic: str
    confidence: float = 0.0
    evidence_chunk_ids: List[str] = Field(default_factory=list)

    @field_validator("evidence_chunk_ids")
    @classmethod
    def _require_evidence(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("AttackMapping must have >=1 evidence_chunk_ids")
        return v


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------


class GeneratedRule(BaseModel):
    rule_id: str
    rule_type: str = "sigma"  # sigma | yara
    title: str
    rule_text: str  # raw YAML or YARA text
    attack_technique: Optional[str] = None
    evidence_chunk_ids: List[str] = Field(default_factory=list)
    confidence: float = 0.0

    @field_validator("evidence_chunk_ids")
    @classmethod
    def _require_evidence(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("GeneratedRule must have >=1 evidence_chunk_ids")
        return v


class ValidationResult(BaseModel):
    rule_id: str
    syntax_valid: bool
    semantic_valid: bool
    malicious_hits: int = 0
    malicious_total: int = 0
    benign_hits: int = 0
    benign_total: int = 0
    false_positive_rate: float = 0.0
    final_verdict: str = "unknown"  # verified | verified_with_caution | weak | unsafe
    warnings: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Final analyst report
# ---------------------------------------------------------------------------


class AnalystReport(BaseModel):
    doc_id: str
    campaign_summary: str
    entities: List[STIXEntity] = Field(default_factory=list)
    relationships: List[STIXRelationship] = Field(default_factory=list)
    attack_mappings: List[AttackMapping] = Field(default_factory=list)
    generated_rules: List[GeneratedRule] = Field(default_factory=list)
    validation_results: List[ValidationResult] = Field(default_factory=list)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    final_confidence: float = 0.0
    final_verdict: str = "unknown"
