"""VeriCTI-RAG — Professor Demo (Phase 1)

A clean, readable, end-to-end demonstration of the VeriCTI-RAG pipeline.
Designed for a professor meeting or thesis proposal defense.

    python run_professor_demo.py              # print to terminal
    python run_professor_demo.py --json       # also write demo_summary.json

Runs entirely offline — no API keys, no internet, no model downloads.
"""

from __future__ import annotations

import json
import sys
import textwrap
from datetime import datetime
from pathlib import Path

# Make ``app`` importable when run from the repo root
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.attacks.poison_ioc import inject_fake_iocs
from app.attacks.poison_prompt_injection import inject_prompt_injection
from app.defense.evidence_verifier import detect_prompt_injection
from app.evaluation.run_poisoning_experiment import compare_clean_vs_poisoned
from app.services import pipeline as svc

ROOT = Path(__file__).resolve().parent
CLEAN_REPORT = ROOT / "data" / "raw_reports" / "demo_clean_cti_report.txt"
POISONED_REPORT = ROOT / "data" / "poisoned_reports" / "demo_poisoned_cti_report.txt"

SEP = "=" * 72


# ---------------------------------------------------------------------------
# Pretty-print helpers
# ---------------------------------------------------------------------------

def _header(num: int, title: str) -> None:
    print(f"\n{SEP}")
    print(f"  STEP {num}: {title}")
    print(SEP)


def _sub(label: str, value: object) -> None:
    print(f"    {label}: {value}")


def _wrap(text: str, indent: int = 6) -> str:
    return textwrap.fill(str(text), width=78, initial_indent=" " * indent,
                         subsequent_indent=" " * indent)


# ---------------------------------------------------------------------------
# Main demo
# ---------------------------------------------------------------------------

def run_professor_demo(write_json: bool = False) -> dict:
    """Run the full demo and return a summary dict."""

    summary: dict = {"timestamp": datetime.now().isoformat(), "phase": "Phase 1 MVP"}
    print(f"\n{'#' * 72}")
    print("#" + "VeriCTI-RAG — Professor Demo (Phase 1 MVP)".center(70) + "#")
    print(f"{'#' * 72}")
    print()
    print("  Project: Poisoning-Resilient and Evidence-Verified")
    print("           Cyber Threat Intelligence RAG for Detection Rule Generation")
    print()
    print("  This demo runs entirely OFFLINE with rule-based extraction.")
    print("  No API keys or model downloads are required.")
    print(f"  Timestamp: {summary['timestamp']}")

    # ------------------------------------------------------------------
    # 1. Ingest clean CTI report
    # ------------------------------------------------------------------
    _header(1, "INGEST CLEAN CTI REPORT")

    clean_text = CLEAN_REPORT.read_text(encoding="utf-8")
    print(f"    Source file : {CLEAN_REPORT.name}")
    print(f"    Length      : {len(clean_text)} characters")
    print(f"    First line  : {clean_text.splitlines()[0]}")

    clean_doc = svc.ingest_file(CLEAN_REPORT, source_type="government",
                                 source="cisa_demo")
    _sub("doc_id", clean_doc.doc_id)
    _sub("title", clean_doc.title)
    _sub("published", clean_doc.published_date)
    _sub("trust_score", clean_doc.trust_score)

    summary["clean_doc"] = {
        "doc_id": clean_doc.doc_id,
        "title": clean_doc.title,
        "trust_score": clean_doc.trust_score,
    }

    # ------------------------------------------------------------------
    # 2. Extract STIX entities + IOCs
    # ------------------------------------------------------------------
    _header(2, "EXTRACT STIX ENTITIES & IOCs")

    ext = svc.extract_for_doc(clean_doc.doc_id)
    entities = ext["entities"]
    relationships = ext["relationships"]
    print(f"    Entities extracted     : {len(entities)}")
    print(f"    Relationships found    : {len(relationships)}")
    print()

    for e in entities:
        etype = e["stix_type"]
        ename = e.get("value") or e["name"]
        ev = e["evidence_chunk_ids"]
        print(f"    [{etype:15s}]  {ename}")
        print(f"                     evidence: {ev}")

    summary["extracted_entities"] = [
        {"type": e["stix_type"], "name": e.get("value") or e["name"],
         "confidence": e["confidence"], "evidence": e["evidence_chunk_ids"]}
        for e in entities
    ]
    summary["extracted_iocs"] = [
        e.get("value") for e in entities if e["stix_type"] == "indicator"
    ]

    # ------------------------------------------------------------------
    # 3. ATT&CK Mapping
    # ------------------------------------------------------------------
    _header(3, "MITRE ATT&CK TECHNIQUE MAPPING")

    mappings = ext["attack_mappings"]
    print(f"    Techniques mapped: {len(mappings)}")
    print()
    for m in mappings:
        print(f"    {m['technique_id']:12s}  {m['technique_name']}")
        print(f"                     tactic: {m['tactic']}")
        print(f"                     confidence: {m['confidence']:.2f}")
        print(f"                     evidence: {m['evidence_chunk_ids']}")

    summary["attack_mappings"] = [
        {"technique_id": m["technique_id"], "technique_name": m["technique_name"],
         "tactic": m["tactic"], "confidence": m["confidence"],
         "evidence": m["evidence_chunk_ids"]}
        for m in mappings
    ]

    # ------------------------------------------------------------------
    # 4. Sigma Rule Generation
    # ------------------------------------------------------------------
    _header(4, "SIGMA DETECTION RULE GENERATION")

    rules = svc.generate_rules_for_doc(clean_doc.doc_id)
    print(f"    Rules generated: {len(rules)}")

    if rules:
        r = rules[0]
        print(f"\n    --- First rule ---")
        _sub("rule_id", r.rule_id)
        _sub("title", r.title)
        _sub("ATT&CK technique", r.attack_technique)
        _sub("confidence", f"{r.confidence:.2f}")
        _sub("evidence_chunks", r.evidence_chunk_ids)
        print(f"\n    Rule YAML:")
        for line in r.rule_text.splitlines():
            print(f"      {line}")

    summary["generated_rules"] = [
        {"rule_id": r.rule_id, "title": r.title, "technique": r.attack_technique,
         "confidence": r.confidence, "evidence": r.evidence_chunk_ids}
        for r in rules
    ]

    # ------------------------------------------------------------------
    # 5. Rule Verification
    # ------------------------------------------------------------------
    _header(5, "RULE VERIFICATION (syntax + semantic + logs)")

    chunks = ext["chunks"]
    chunks_by_id = {c["chunk_id"]: c for c in chunks}

    validations = []
    for r in rules:
        v = svc.verify_rule(r, chunks_by_id)
        validations.append(v)
        print(f"    [{v.rule_id}]")
        _sub("syntax_valid", v.syntax_valid)
        _sub("semantic_valid", v.semantic_valid)
        _sub("malicious hits", f"{v.malicious_hits}/{v.malicious_total}")
        _sub("benign false-pos", f"{v.benign_hits}/{v.benign_total}")
        _sub("false_positive_rate", f"{v.false_positive_rate:.2%}")
        _sub("verdict", v.final_verdict)
        print()

    summary["validation_results"] = [
        {"rule_id": v.rule_id, "syntax_valid": v.syntax_valid,
         "semantic_valid": v.semantic_valid,
         "tp": f"{v.malicious_hits}/{v.malicious_total}",
         "fp": f"{v.benign_hits}/{v.benign_total}",
         "fpr": v.false_positive_rate, "verdict": v.final_verdict}
        for v in validations
    ]

    # ------------------------------------------------------------------
    # 6. Evidence Links
    # ------------------------------------------------------------------
    _header(6, "EVIDENCE PROVENANCE LINKS")

    print("    VeriCTI-RAG links EVERY output to source evidence chunks.")
    print("    This is the key difference from a normal RAG system.\n")
    evidence_links = []
    for e in entities[:5]:
        for cid in e["evidence_chunk_ids"]:
            ch = chunks_by_id.get(cid, {})
            snippet = (ch.get("text") or "")[:80].replace("\n", " ")
            print(f"    Entity: {e.get('value') or e['name']}")
            print(f"      chunk: {cid}")
            print(f"      text:  \"{snippet}...\"")
            print()
            evidence_links.append({
                "entity": e.get("value") or e["name"],
                "chunk_id": cid,
                "snippet": snippet,
            })

    summary["evidence_links"] = evidence_links

    # ------------------------------------------------------------------
    # 7. Poisoning Attack + Re-extraction
    # ------------------------------------------------------------------
    _header(7, "POISONING ATTACK — Clean vs Poisoned")

    poisoned_text = POISONED_REPORT.read_text(encoding="utf-8")

    # Check for prompt injection
    injections = detect_prompt_injection(poisoned_text)
    print(f"    Prompt injection patterns detected: {len(injections)}")
    for pat in injections:
        print(f"      ⚠  matched: {pat}")

    poisoned_doc = svc.ingest_text(
        poisoned_text,
        title_fallback="ShadowLoader (POISONED)",
        source="poisoned_demo",
        source_type="unknown",
    )
    _sub("poisoned doc_id", poisoned_doc.doc_id)
    _sub("poisoned trust_score", poisoned_doc.trust_score)

    print("\n    Running clean-vs-poisoned comparison...")
    cmp = compare_clean_vs_poisoned(clean_doc.doc_id, poisoned_doc.doc_id)

    print(f"\n    Clean entities    : {cmp['n_clean_entities']}")
    print(f"    Poisoned entities : {cmp['n_poisoned_entities']}")
    print(f"    Newly introduced  : {cmp['newly_introduced_iocs']}")
    print(f"    ATT&CK overlap    : {cmp['attack_mapping_overlap']:.2f}")
    print(f"    Evidence faith.   : clean={cmp['evidence_faithfulness_clean']:.2f}  "
          f"poisoned={cmp['evidence_faithfulness_poisoned']:.2f}")
    print(f"    Poisoning success : {cmp['poisoning_success_rate_estimate']:.2f}")

    summary["poisoning_results"] = cmp

    # ------------------------------------------------------------------
    # 8. Final Analyst Report
    # ------------------------------------------------------------------
    _header(8, "FINAL ANALYST REPORT")

    report = svc.build_analyst_report(clean_doc.doc_id)

    print(f"    Document       : {report.doc_id}")
    print(f"    Verdict        : {report.final_verdict}")
    print(f"    Confidence     : {report.final_confidence:.2f}")
    print(f"    Entities       : {len(report.entities)}")
    print(f"    ATT&CK maps    : {len(report.attack_mappings)}")
    print(f"    Sigma rules    : {len(report.generated_rules)}")
    print(f"    Validations    : {len(report.validation_results)}")
    print(f"    Warnings       : {len(report.warnings)}")

    if report.warnings:
        print("\n    Warnings:")
        for w in report.warnings[:10]:
            print(f"      ⚠  {w}")

    summary["final_confidence"] = report.final_confidence
    summary["final_verdict"] = report.final_verdict
    summary["warnings"] = report.warnings

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print(f"\n{SEP}")
    print("  DEMO COMPLETE — Phase 1 MVP")
    print(SEP)
    print("""
    What this demo showed:
    ✓ Ingested a clean CTI report (offline, no API keys)
    ✓ Extracted STIX entities and IOCs with evidence links
    ✓ Mapped behaviors to MITRE ATT&CK techniques
    ✓ Generated Sigma detection rules from evidence
    ✓ Verified rules: syntax, semantic grounding, log execution
    ✓ Showed evidence provenance for every output
    ✓ Applied a poisoning attack and compared outputs
    ✓ Produced a final analyst report with confidence + warnings

    What is NOT claimed:
    ✗ This is not a finished A* paper — it is a Phase 1 prototype
    ✗ No real-world SOC deployment — research demo only
    ✗ Extraction is rule-based; LLM augmentation planned for Phase 2
    """)

    # Write JSON summary
    if write_json:
        out_path = ROOT / "demo_summary.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, default=str)
        print(f"    JSON summary written to: {out_path}")

    return summary


if __name__ == "__main__":
    write = "--json" in sys.argv
    run_professor_demo(write_json=True)
