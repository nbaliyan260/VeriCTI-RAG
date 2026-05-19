"""Tests for the professor demo — ensures the demo pipeline produces correct output."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Ensure repo root is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture(scope="module")
def demo_results():
    """Run the professor demo once and cache the result for all tests."""
    from run_professor_demo import run_professor_demo
    return run_professor_demo(write_json=False)


def test_demo_runs_without_crash(demo_results):
    """The professor demo completes and returns a summary dict."""
    assert isinstance(demo_results, dict)
    assert "phase" in demo_results
    assert demo_results["phase"] == "Phase 1 MVP"


def test_extracted_entities_non_empty(demo_results):
    """At least one entity was extracted from the clean report."""
    ents = demo_results.get("extracted_entities", [])
    assert len(ents) > 0, "Expected at least 1 extracted entity"


def test_extracted_iocs_non_empty(demo_results):
    """At least one IOC (indicator) was extracted."""
    iocs = demo_results.get("extracted_iocs", [])
    assert len(iocs) > 0, "Expected at least 1 IOC"


def test_attack_mappings_non_empty(demo_results):
    """At least one ATT&CK mapping was produced."""
    mappings = demo_results.get("attack_mappings", [])
    assert len(mappings) > 0, "Expected at least 1 ATT&CK mapping"


def test_generated_rules_non_empty(demo_results):
    """At least one Sigma rule was generated."""
    rules = demo_results.get("generated_rules", [])
    assert len(rules) > 0, "Expected at least 1 generated Sigma rule"


def test_evidence_links_exist(demo_results):
    """Every extracted entity has at least one evidence link."""
    for e in demo_results.get("extracted_entities", []):
        assert e.get("evidence"), f"Entity {e.get('name')} has no evidence link"


def test_validation_results_exist(demo_results):
    """At least one rule verification result exists."""
    vals = demo_results.get("validation_results", [])
    assert len(vals) > 0, "Expected at least 1 validation result"


def test_poisoning_comparison_returns_data(demo_results):
    """Clean vs poisoned comparison produced a result dict."""
    poison = demo_results.get("poisoning_results", {})
    assert poison, "Poisoning comparison returned empty"
    assert "n_clean_entities" in poison
    assert "n_poisoned_entities" in poison
    assert "newly_introduced_iocs" in poison


def test_poisoning_introduces_new_iocs(demo_results):
    """The poisoned report introduces at least one new IOC not in clean."""
    poison = demo_results.get("poisoning_results", {})
    assert len(poison.get("newly_introduced_iocs", [])) > 0, \
        "Poisoning should introduce at least 1 new IOC"


def test_final_report_has_confidence(demo_results):
    """The final report includes a numeric confidence score."""
    conf = demo_results.get("final_confidence")
    assert conf is not None, "Missing final_confidence"
    assert 0.0 <= conf <= 1.0, f"Confidence {conf} out of range"


def test_final_report_has_verdict(demo_results):
    """The final report includes a verdict string."""
    verdict = demo_results.get("final_verdict")
    assert verdict in {"verified", "verified_with_caution", "weak", "unsafe"}, \
        f"Unexpected verdict: {verdict}"


def test_warnings_present(demo_results):
    """The final report includes at least one warning."""
    warnings = demo_results.get("warnings", [])
    assert len(warnings) > 0, "Expected at least 1 warning"
