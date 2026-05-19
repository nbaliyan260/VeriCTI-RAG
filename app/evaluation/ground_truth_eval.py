"""Evaluate extraction accuracy against ground-truth JSON files.

Ground truth files live under ``data/ground_truth/<report_stem>.json`` and
follow this schema::

    {
      "doc": "sample_apt_report.txt",
      "stix_entities": [
          {"stix_type": "malware", "name": "ExampleRAT"},
          {"stix_type": "indicator", "value": "example-c2.com"},
          ...
      ],
      "attack_techniques": ["T1059.001", "T1105", ...]
    }

This module computes precision, recall and F1 for:
* STIX entity extraction (by ``(stix_type, name_lower_or_value_lower)``)
* ATT&CK technique mapping (by ``technique_id``)

Usage::

    python -m app.evaluation.ground_truth_eval
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

from ..core.config import get_settings
from ..services import pipeline as svc
from .metrics import precision_recall_f1


def _normalise_entity(e: dict) -> str:
    """Canonical key for a STIX entity."""
    val = (e.get("value") or e.get("name") or "").lower().strip()
    return f"{e.get('stix_type', 'unknown')}:{val}"


def _load_ground_truth(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def evaluate_report(report_path: Path, gt_path: Path) -> Dict:
    """Ingest a report, extract, and compare against ground truth."""
    doc = svc.ingest_file(report_path, source_type="vendor_blog", source="gt_eval")
    ext = svc.extract_for_doc(doc.doc_id)
    gt = _load_ground_truth(gt_path)

    # ----- Entity evaluation -----
    gold_entities: Set[str] = set()
    for e in gt.get("stix_entities", []):
        gold_entities.add(_normalise_entity(e))

    pred_entities: Set[str] = set()
    for e in ext["entities"]:
        pred_entities.add(_normalise_entity(e))

    ent_p, ent_r, ent_f1 = precision_recall_f1(pred_entities, gold_entities)

    # ----- ATT&CK evaluation -----
    gold_tech: Set[str] = set(gt.get("attack_techniques", []))
    pred_tech: Set[str] = {m["technique_id"] for m in ext["attack_mappings"]}

    tech_p, tech_r, tech_f1 = precision_recall_f1(pred_tech, gold_tech)

    return {
        "report": report_path.name,
        "doc_id": doc.doc_id,
        "entity_precision": round(ent_p, 4),
        "entity_recall": round(ent_r, 4),
        "entity_f1": round(ent_f1, 4),
        "entity_pred_count": len(pred_entities),
        "entity_gold_count": len(gold_entities),
        "entity_missing": sorted(gold_entities - pred_entities),
        "entity_extra": sorted(pred_entities - gold_entities),
        "technique_precision": round(tech_p, 4),
        "technique_recall": round(tech_r, 4),
        "technique_f1": round(tech_f1, 4),
        "technique_pred": sorted(pred_tech),
        "technique_gold": sorted(gold_tech),
        "technique_missing": sorted(gold_tech - pred_tech),
        "technique_extra": sorted(pred_tech - gold_tech),
    }


def run_all() -> List[Dict]:
    """Evaluate all reports that have a matching ground-truth JSON."""
    s = get_settings()
    gt_dir = s.data_dir / "ground_truth"
    report_dir = s.data_dir / "raw_reports"
    results: List[Dict] = []
    for gt_file in sorted(gt_dir.glob("*.json")):
        gt = _load_ground_truth(gt_file)
        report_file = report_dir / gt.get("doc", gt_file.stem + ".txt")
        if not report_file.exists():
            print(f"[skip] {report_file} not found for GT {gt_file.name}")
            continue
        print(f"[eval] {report_file.name} vs {gt_file.name}")
        r = evaluate_report(report_file, gt_file)
        results.append(r)
    return results


def main() -> None:
    results = run_all()
    if not results:
        print("No ground-truth / report pairs found. Nothing to evaluate.")
        return
    print("\n" + "=" * 72)
    print("GROUND TRUTH EVALUATION RESULTS")
    print("=" * 72)
    for r in results:
        print(f"\n--- {r['report']} ---")
        print(f"  STIX entities : P={r['entity_precision']:.2f}  "
              f"R={r['entity_recall']:.2f}  F1={r['entity_f1']:.2f}  "
              f"(pred={r['entity_pred_count']}, gold={r['entity_gold_count']})")
        if r["entity_missing"]:
            print(f"    missing: {r['entity_missing']}")
        if r["entity_extra"]:
            print(f"    extra:   {r['entity_extra']}")
        print(f"  ATT&CK techs  : P={r['technique_precision']:.2f}  "
              f"R={r['technique_recall']:.2f}  F1={r['technique_f1']:.2f}")
        if r["technique_missing"]:
            print(f"    missing: {r['technique_missing']}")
        if r["technique_extra"]:
            print(f"    extra:   {r['technique_extra']}")

    # Aggregate
    avg_e_f1 = sum(r["entity_f1"] for r in results) / len(results)
    avg_t_f1 = sum(r["technique_f1"] for r in results) / len(results)
    print(f"\n--- Macro avg (n={len(results)}) ---")
    print(f"  Entity F1   = {avg_e_f1:.4f}")
    print(f"  Technique F1= {avg_t_f1:.4f}")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    # Allow running via: python -m app.evaluation.ground_truth_eval
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    main()
