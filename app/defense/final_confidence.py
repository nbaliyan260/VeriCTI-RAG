"""Final confidence score combining evidence, trust, freshness, graph, validation."""

from __future__ import annotations

from typing import Dict

from ..core.config import get_settings


def compute_final_confidence(
    *,
    evidence_support: float,
    trust: float,
    freshness: float,
    graph_consistency: float,
    rule_validation: float,
) -> float:
    s = get_settings()
    raw = (
        s.w_evidence * evidence_support
        + s.w_trust * trust
        + s.w_freshness * freshness
        + s.w_graph * graph_consistency
        + s.w_validation * rule_validation
    )
    return max(0.0, min(1.0, raw))


def verdict_from_confidence(conf: float, *, warnings: int = 0) -> str:
    if conf >= 0.8 and warnings == 0:
        return "verified"
    if conf >= 0.6:
        return "verified_with_caution"
    if conf >= 0.4:
        return "weak"
    return "unsafe"
