from app.services import pipeline as svc


def test_bm25_retrieval_after_ingest():
    doc = svc.ingest_text(
        "The malware used PowerShell encoded commands to download a payload.",
        title_fallback="t", source="x", source_type="vendor_blog",
    )
    res = svc.search_chunks("powershell encoded", top_k=3)
    assert res, "expected at least one matching chunk"
    assert any(r["chunk"].get("doc_id") == doc.doc_id for r in res)
