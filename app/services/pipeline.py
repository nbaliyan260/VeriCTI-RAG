"""End-to-end VeriCTI-RAG pipeline.

Orchestrates ingestion -> retrieval -> extraction -> graph -> rules ->
verification -> analyst report. This is what the API endpoints and CLI
demo both call into.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from ..core.config import get_settings
from ..core.db import (
    get_chunks,
    get_document,
    list_documents,
    upsert_chunks,
    upsert_document,
)
from ..core.schemas import (
    AnalystReport,
    AttackMapping,
    Document,
    GeneratedRule,
    STIXEntity,
    STIXRelationship,
    ValidationResult,
)
from ..defense.evidence_verifier import (
    detect_prompt_injection,
    verify_attack_support,
    verify_entity_support,
    verify_relationship_support,
    verify_rule_support,
)
from ..defense.final_confidence import compute_final_confidence, verdict_from_confidence
from ..defense.freshness_scorer import freshness_score
from ..defense.provenance_checker import check_provenance
from ..defense.trust_scorer import initial_trust
from ..extraction.attack_mapper import map_attack
from ..extraction.stix_extractor import extract_stix
from ..graph.consistency_checker import check_consistency
from ..graph.contradiction_detector import detect_contradictions
from ..graph.graph_builder import build_graph, graph_to_dict
from ..ingestion.chunker import chunk_text
from ..ingestion.metadata_extractor import extract_metadata
from ..ingestion.pdf_loader import load_pdf
from ..ingestion.text_loader import load_text
from ..retrieval.hybrid_retriever import HybridRetriever
from ..retrieval.vector_retriever import VectorRetriever
from ..rules.rule_executor import collect_log_pair, execute_rule
from ..rules.sigma_generator import generate_rules
from ..rules.sigma_validator import validate_sigma


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------


def _doc_id_for(path: Path, content: str) -> str:
    h = hashlib.sha1((str(path) + content[:512]).encode()).hexdigest()[:10]
    stem = path.stem.lower().replace(" ", "_") if path else "doc"
    return f"{stem}_{h}"


def ingest_file(path: str | Path, *, source_type: str = "unknown",
                source: Optional[str] = None) -> Document:
    p = Path(path)
    raw = p.read_bytes()
    if p.suffix.lower() == ".pdf":
        text = load_pdf(raw)
    else:
        text = load_text(raw)
    return ingest_text(text, file_path=str(p), title_fallback=p.name,
                        source=source or p.parent.name, source_type=source_type)


def ingest_text(text: str, *, file_path: Optional[str] = None,
                title_fallback: str = "Untitled Report",
                source: str = "unknown",
                source_type: str = "unknown",
                doc_id: Optional[str] = None) -> Document:
    meta = extract_metadata(text, fallback_title=title_fallback)
    p = Path(file_path) if file_path else Path("inline")
    did = doc_id or _doc_id_for(p, text)
    doc = Document(
        doc_id=did,
        title=meta["title"] or title_fallback,
        source=source,
        source_type=source_type,
        published_date=meta["published_date"],
        ingested_at=datetime.now(timezone.utc).isoformat(),
        trust_score=initial_trust(source_type),
        file_path=str(file_path) if file_path else None,
    )
    upsert_document(doc.model_dump())

    chunks = chunk_text(text, doc_id=did)
    upsert_chunks([c.model_dump() for c in chunks])

    # Index into vector store
    try:
        v = VectorRetriever()
        v.add([c.model_dump() for c in chunks])
    except Exception:
        # Vector indexing is best-effort. BM25 still works.
        pass
    return doc


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def extract_for_doc(doc_id: str, *, query: Optional[str] = None,
                    top_k: Optional[int] = None) -> Dict:
    doc = get_document(doc_id)
    if not doc:
        raise ValueError(f"Unknown doc_id {doc_id}")
    chunks = get_chunks(doc_id)
    # Provide raw document text to extractors so they can detect chunk-boundary
    # artifacts (e.g., an IOC split where a chunk begins mid-token).
    original_text = None
    try:
        fp = doc.get("file_path")
        if fp:
            original_text = Path(fp).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        original_text = None
    if original_text:
        chunks = [dict(c, original_text=original_text) for c in chunks]
    if query:
        retriever = HybridRetriever()
        results = retriever.search(query, k=top_k)
        retrieved_ids = {c["chunk_id"] for c, _ in results if c.get("doc_id") == doc_id}
        chunks = [c for c in chunks if c["chunk_id"] in retrieved_ids] or chunks
    entities, relationships = extract_stix(chunks)
    mappings = map_attack(chunks)

    chunks_by_id = {c["chunk_id"]: c for c in chunks}
    # Annotate with support scores
    annotated_entities = []
    for e in entities:
        e.confidence = max(e.confidence, verify_entity_support(e, chunks_by_id))
        annotated_entities.append(e)
    annotated_rels = []
    for r in relationships:
        r.confidence = max(r.confidence, verify_relationship_support(r, chunks_by_id))
        annotated_rels.append(r)
    annotated_mappings = []
    for m in mappings:
        m.confidence = max(m.confidence, verify_attack_support(m, chunks_by_id))
        annotated_mappings.append(m)

    return {
        "doc_id": doc_id,
        "document": doc,
        "chunks": chunks,
        "entities": [e.model_dump() for e in annotated_entities],
        "relationships": [r.model_dump() for r in annotated_rels],
        "attack_mappings": [m.model_dump() for m in annotated_mappings],
    }


def search_chunks(query: str, top_k: Optional[int] = None) -> List[Dict]:
    retriever = HybridRetriever()
    results = retriever.search(query, k=top_k)
    return [{"chunk": c, "score": float(s)} for c, s in results]


# ---------------------------------------------------------------------------
# Rule generation + verification
# ---------------------------------------------------------------------------


def generate_rules_for_doc(doc_id: str) -> List[GeneratedRule]:
    ext = extract_for_doc(doc_id)
    mappings = [AttackMapping(**m) for m in ext["attack_mappings"]]
    return generate_rules(doc_id, mappings)


def verify_rule(rule: GeneratedRule, chunks_by_id: Dict[str, dict]) -> ValidationResult:
    s = get_settings()
    syntax_ok, syntax_errs = validate_sigma(rule.rule_text)
    semantic_ok, support = verify_rule_support(rule, chunks_by_id)

    mal_dir = s.data_dir / "logs_malicious"
    ben_dir = s.data_dir / "logs_benign"
    mal_log, ben_log = collect_log_pair(mal_dir, ben_dir, rule.attack_technique or "default")
    log_stats = execute_rule(rule.rule_text, malicious_log=mal_log, benign_log=ben_log)

    fpr = (log_stats["benign_hits"] / log_stats["benign_total"]
           if log_stats["benign_total"] else 0.0)
    tpr = (log_stats["malicious_hits"] / log_stats["malicious_total"]
           if log_stats["malicious_total"] else 0.0)

    warnings = list(syntax_errs)
    if not semantic_ok:
        warnings.append("rule conditions not strongly supported by evidence")
    if fpr > 0.1:
        warnings.append(f"high benign FPR ({fpr:.2%})")

    if syntax_ok and semantic_ok and tpr >= 0.5 and fpr <= 0.1:
        verdict = "verified"
    elif syntax_ok and (semantic_ok or tpr >= 0.5):
        verdict = "verified_with_caution"
    elif syntax_ok:
        verdict = "weak"
    else:
        verdict = "unsafe"

    return ValidationResult(
        rule_id=rule.rule_id,
        syntax_valid=syntax_ok,
        semantic_valid=semantic_ok,
        malicious_hits=log_stats["malicious_hits"],
        malicious_total=log_stats["malicious_total"],
        benign_hits=log_stats["benign_hits"],
        benign_total=log_stats["benign_total"],
        false_positive_rate=fpr,
        final_verdict=verdict,
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# Final report
# ---------------------------------------------------------------------------


def build_analyst_report(doc_id: str) -> AnalystReport:
    ext = extract_for_doc(doc_id)
    doc = ext["document"]
    chunks = ext["chunks"]
    chunks_by_id = {c["chunk_id"]: c for c in chunks}
    entities = [STIXEntity(**e) for e in ext["entities"]]
    rels = [STIXRelationship(**r) for r in ext["relationships"]]
    mappings = [AttackMapping(**m) for m in ext["attack_mappings"]]
    rules = generate_rules(doc_id, mappings)

    # Build graph + run consistency checks
    g = build_graph(
        documents=[doc],
        chunks=chunks,
        entities=entities,
        relationships=rels,
        attack_mappings=mappings,
        rules=rules,
    )
    cons = check_consistency(g)
    contradictions = detect_contradictions(g, chunks_by_id)

    # Provenance
    prov = check_provenance(
        chunks=chunks, entities=entities, relationships=rels,
        attack_mappings=mappings, rules=rules,
    )

    # Verification
    validations = [verify_rule(r, chunks_by_id) for r in rules]

    # Confidence inputs
    evidence_support = (
        sum(e.confidence for e in entities) / max(1, len(entities))
        if entities else 0.0
    )
    trust = float(doc.get("trust_score") or 0.5)
    fresh = freshness_score(doc.get("published_date"))
    n_warn = sum(len(v) for v in cons.values()) + len(contradictions) + sum(
        len(x) for x in prov.values()
    )
    graph_consistency = max(0.0, 1.0 - 0.1 * n_warn)
    rule_val = (
        sum(1 for v in validations if v.final_verdict in ("verified", "verified_with_caution"))
        / max(1, len(validations))
    )

    final_conf = compute_final_confidence(
        evidence_support=evidence_support,
        trust=trust,
        freshness=fresh,
        graph_consistency=graph_consistency,
        rule_validation=rule_val,
    )

    warnings: List[str] = []
    for cat, msgs in cons.items():
        warnings.extend(f"[{cat}] {m}" for m in msgs)
    for c in contradictions:
        warnings.append(f"[contradiction] {c}")
    for cat, msgs in prov.items():
        warnings.extend(f"[provenance:{cat}] {m}" for m in msgs)
    for ch in chunks:
        if detect_prompt_injection(ch["text"]):
            warnings.append(f"[prompt_injection] chunk {ch['chunk_id']} contains adversarial instructions")

    verdict = verdict_from_confidence(final_conf, warnings=len(warnings))

    evidence_payload = [
        {
            "claim": e.name,
            "source_chunks": e.evidence_chunk_ids,
            "support_score": e.confidence,
        }
        for e in entities[:20]
    ]

    summary = (
        f"Report '{doc.get('title')}' from source '{doc.get('source')}'. "
        f"{len(entities)} STIX entities, {len(mappings)} ATT&CK mappings, "
        f"{len(rules)} Sigma rules generated."
    )

    return AnalystReport(
        doc_id=doc_id,
        campaign_summary=summary,
        entities=entities,
        relationships=rels,
        attack_mappings=mappings,
        generated_rules=rules,
        validation_results=validations,
        evidence=evidence_payload,
        warnings=warnings,
        final_confidence=final_conf,
        final_verdict=verdict,
    )


def graph_for_doc(doc_id: str) -> Dict:
    ext = extract_for_doc(doc_id)
    doc = ext["document"]
    chunks = ext["chunks"]
    entities = [STIXEntity(**e) for e in ext["entities"]]
    rels = [STIXRelationship(**r) for r in ext["relationships"]]
    mappings = [AttackMapping(**m) for m in ext["attack_mappings"]]
    rules = generate_rules(doc_id, mappings)
    g = build_graph(documents=[doc], chunks=chunks, entities=entities,
                    relationships=rels, attack_mappings=mappings, rules=rules)
    return graph_to_dict(g)


def list_known_documents() -> List[Dict]:
    return list_documents()
