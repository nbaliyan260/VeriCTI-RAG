"""FastAPI entrypoint for VeriCTI-RAG."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .attacks.poison_attack_mapping import inject_wrong_attack_mapping
from .attacks.poison_false_attribution import inject_false_attribution
from .attacks.poison_ioc import inject_fake_iocs
from .attacks.poison_prompt_injection import inject_prompt_injection
from .attacks.poison_stale_ioc import inject_stale_iocs
from .core.config import get_settings
from .core.db import get_chunks
from .core.schemas import GeneratedRule
from .services import pipeline as svc


app = FastAPI(
    title="VeriCTI-RAG",
    description="Poisoning-Resilient and Evidence-Verified CTI RAG",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class IngestTextRequest(BaseModel):
    text: str
    title: Optional[str] = None
    source: str = "unknown"
    source_type: str = "unknown"


class ExtractRequest(BaseModel):
    doc_id: Optional[str] = None
    query: Optional[str] = None
    top_k: Optional[int] = None


class GenerateRuleRequest(BaseModel):
    doc_id: str


class VerifyRuleRequest(BaseModel):
    rule_id: str
    rule_text: str
    attack_technique: Optional[str] = None
    evidence_chunk_ids: List[str]
    title: Optional[str] = "uploaded-rule"


class PoisonRequest(BaseModel):
    text: str
    attacks: List[str] = [
        "fake_ioc", "wrong_attack", "false_attribution",
        "prompt_injection", "stale_ioc",
    ]


class EvaluateRequest(BaseModel):
    clean_doc_id: str
    poisoned_doc_id: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/")
def root():
    return {"name": "VeriCTI-RAG", "version": app.version, "ok": True}


@app.get("/documents")
def documents():
    return svc.list_known_documents()


@app.post("/ingest")
async def ingest(
    file: UploadFile | None = File(default=None),
    text: str = Form(default=""),
    title: str = Form(default=""),
    source: str = Form(default="unknown"),
    source_type: str = Form(default="unknown"),
):
    if file is not None:
        s = get_settings()
        target = s.data_dir / "uploads" / file.filename
        target.parent.mkdir(parents=True, exist_ok=True)
        content = await file.read()
        target.write_bytes(content)
        doc = svc.ingest_file(target, source=source or "uploaded",
                               source_type=source_type)
    elif text:
        doc = svc.ingest_text(text, title_fallback=title or "Inline Report",
                               source=source, source_type=source_type)
    else:
        raise HTTPException(400, "Provide either 'file' or 'text'.")
    return doc.model_dump()


@app.post("/ingest/text")
def ingest_text_endpoint(req: IngestTextRequest):
    doc = svc.ingest_text(req.text, title_fallback=req.title or "Inline Report",
                           source=req.source, source_type=req.source_type)
    return doc.model_dump()


@app.post("/extract")
def extract(req: ExtractRequest):
    if not req.doc_id and not req.query:
        raise HTTPException(400, "Provide doc_id or query")
    if req.doc_id:
        return svc.extract_for_doc(req.doc_id, query=req.query, top_k=req.top_k)
    # Query-only: return matching chunks
    return {"chunks": svc.search_chunks(req.query or "", top_k=req.top_k)}


@app.post("/generate-rule")
def generate_rule(req: GenerateRuleRequest):
    rules = svc.generate_rules_for_doc(req.doc_id)
    return {
        "doc_id": req.doc_id,
        "rules": [r.model_dump() for r in rules],
    }


@app.post("/verify-rule")
def verify_rule(req: VerifyRuleRequest):
    # Build a GeneratedRule from the payload
    rule = GeneratedRule(
        rule_id=req.rule_id,
        rule_type="sigma",
        title=req.title or "uploaded-rule",
        rule_text=req.rule_text,
        attack_technique=req.attack_technique,
        evidence_chunk_ids=req.evidence_chunk_ids,
        confidence=0.5,
    )
    # Build chunk lookup from db for all referenced chunks
    chunks_by_id = {}
    for cid in req.evidence_chunk_ids:
        for c in svc.search_chunks(cid):
            ch = c["chunk"]
            chunks_by_id[ch["chunk_id"]] = ch
    # Fallback: load chunks of those docs
    if not chunks_by_id:
        # Try by directly looking up all chunks of all docs (small prototype)
        for d in svc.list_known_documents():
            for ch in get_chunks(d["doc_id"]):
                chunks_by_id[ch["chunk_id"]] = ch
    result = svc.verify_rule(rule, chunks_by_id)
    return result.model_dump()


_POISON_FNS = {
    "fake_ioc": inject_fake_iocs,
    "wrong_attack": inject_wrong_attack_mapping,
    "false_attribution": inject_false_attribution,
    "prompt_injection": inject_prompt_injection,
    "stale_ioc": inject_stale_iocs,
}


@app.post("/poison")
def poison(req: PoisonRequest):
    variants = {}
    for name in req.attacks:
        fn = _POISON_FNS.get(name)
        if fn is None:
            continue
        variants[name] = fn(req.text)
    return {"variants": variants}


@app.post("/evaluate")
def evaluate(req: EvaluateRequest):
    from .evaluation.run_poisoning_experiment import compare_clean_vs_poisoned

    return compare_clean_vs_poisoned(req.clean_doc_id, req.poisoned_doc_id)


@app.get("/graph/{doc_id}")
def graph(doc_id: str):
    return svc.graph_for_doc(doc_id)


@app.get("/report/{doc_id}")
def report(doc_id: str):
    return svc.build_analyst_report(doc_id).model_dump()
