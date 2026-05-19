from app.attacks.poison_ioc import inject_fake_iocs
from app.attacks.poison_prompt_injection import inject_prompt_injection
from app.defense.evidence_verifier import (
    detect_prompt_injection,
    verify_entity_support,
)
from app.defense.final_confidence import compute_final_confidence, verdict_from_confidence
from app.defense.freshness_scorer import freshness_score
from app.core.schemas import STIXEntity


def test_prompt_injection_detected():
    p = inject_prompt_injection("clean text\n\nbody")["poisoned_text"]
    assert detect_prompt_injection(p)


def test_fake_ioc_attack_introduces_iocs():
    out = inject_fake_iocs("Original report body.\n\nMore text.")
    assert "beaconing" in out["poisoned_text"].lower()
    assert out["ground_truth_fake_iocs"]["domains"]


def test_entity_support_score_zero_when_missing():
    e = STIXEntity(entity_id="e1", stix_type="indicator", name="bad.com",
                   value="bad.com", confidence=0.5, evidence_chunk_ids=["c1"])
    chunks = {"c1": {"text": "no mention here", "chunk_id": "c1"}}
    assert verify_entity_support(e, chunks) == 0.0


def test_entity_support_score_one_when_present():
    e = STIXEntity(entity_id="e1", stix_type="indicator", name="bad.com",
                   value="bad.com", confidence=0.5, evidence_chunk_ids=["c1"])
    chunks = {"c1": {"text": "evidence says bad.com is c2", "chunk_id": "c1"}}
    assert verify_entity_support(e, chunks) == 1.0


def test_freshness_score_recent_higher_than_old():
    assert freshness_score("2026-04-01") > freshness_score("2020-01-01")


def test_final_confidence_and_verdict():
    c = compute_final_confidence(
        evidence_support=0.9, trust=0.9, freshness=0.9,
        graph_consistency=0.9, rule_validation=1.0,
    )
    assert 0.0 <= c <= 1.0
    assert verdict_from_confidence(c, warnings=0) in {"verified", "verified_with_caution"}
