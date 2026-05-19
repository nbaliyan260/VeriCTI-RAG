"""End-to-end VeriCTI-RAG demo.

Ingests the bundled sample report, runs extraction + rule generation +
verification, generates a poisoned variant, and prints a final analyst
report. Use this script to validate the local install:

    python run_demo.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Make ``app`` importable when run from the repo root
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.attacks.poison_ioc import inject_fake_iocs
from app.attacks.poison_prompt_injection import inject_prompt_injection
from app.evaluation.report_generator import report_to_markdown
from app.evaluation.run_poisoning_experiment import compare_clean_vs_poisoned
from app.services import pipeline as svc


SAMPLE = Path(__file__).resolve().parent / "data" / "raw_reports" / "sample_apt_report.txt"


def main() -> None:
    print("=== VeriCTI-RAG demo ===")

    print(f"\n[1] Ingesting clean report: {SAMPLE}")
    clean_doc = svc.ingest_file(SAMPLE, source_type="vendor_blog",
                                 source="sample_apt")
    print(f"    doc_id={clean_doc.doc_id} title={clean_doc.title!r} "
          f"published={clean_doc.published_date} trust={clean_doc.trust_score}")

    print("\n[2] Generating poisoned variant (fake IOC + prompt injection)")
    raw = SAMPLE.read_text(encoding="utf-8")
    poisoned_text = inject_prompt_injection(inject_fake_iocs(raw)["poisoned_text"])["poisoned_text"]
    poisoned_doc = svc.ingest_text(
        poisoned_text,
        title_fallback="ExampleRAT (poisoned)",
        source="poisoned_sample_apt",
        source_type="unknown",
    )
    print(f"    poisoned doc_id={poisoned_doc.doc_id}")

    print("\n[3] Building analyst report for clean document")
    report = svc.build_analyst_report(clean_doc.doc_id)
    print(report_to_markdown(report))

    print("\n[4] Clean vs poisoned comparison")
    cmp = compare_clean_vs_poisoned(clean_doc.doc_id, poisoned_doc.doc_id)
    print(json.dumps(cmp, indent=2, default=str))


if __name__ == "__main__":
    main()
