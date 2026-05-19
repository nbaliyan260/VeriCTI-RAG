from pathlib import Path

from app.core.config import get_settings
from app.core.schemas import AttackMapping
from app.rules.rule_executor import execute_rule
from app.rules.sigma_generator import generate_rules
from app.rules.sigma_validator import validate_sigma


def test_generate_rule_for_powershell_is_valid_yaml_and_has_evidence():
    m = AttackMapping(
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic="Execution",
        confidence=0.9,
        evidence_chunk_ids=["c1"],
    )
    rules = generate_rules("doc1", [m])
    assert rules, "expected at least one generated rule"
    r = rules[0]
    assert r.attack_technique == "T1059.001"
    ok, errs = validate_sigma(r.rule_text)
    assert ok, errs


def test_rule_executor_detects_encoded_powershell():
    m = AttackMapping(
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic="Execution",
        confidence=0.9,
        evidence_chunk_ids=["c1"],
    )
    rule = generate_rules("doc1", [m])[0]
    s = get_settings()
    mal = Path(s.data_dir) / "logs_malicious" / "T1059.001.jsonl"
    ben = Path(s.data_dir) / "logs_benign" / "T1059.001.jsonl"
    # If the test env's data dir is isolated, copy sample logs from repo
    if not mal.exists():
        repo = Path(__file__).resolve().parents[1]
        mal.parent.mkdir(parents=True, exist_ok=True)
        ben.parent.mkdir(parents=True, exist_ok=True)
        mal.write_text((repo / "data" / "logs_malicious" / "T1059.001.jsonl").read_text())
        ben.write_text((repo / "data" / "logs_benign" / "T1059.001.jsonl").read_text())
    stats = execute_rule(rule.rule_text, malicious_log=mal, benign_log=ben)
    assert stats["malicious_total"] > 0
    assert stats["malicious_hits"] >= stats["malicious_total"] - 1
