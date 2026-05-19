"""VeriCTI-RAG Streamlit dashboard.

The Streamlit app communicates with the FastAPI backend over HTTP. The
backend host is configurable via the ``VERICTI_API`` env var (default
http://localhost:8000).

Tabs:
    1. Upload Report
    2. Extracted CTI
    3. Evidence Graph
    4. Generated Sigma Rule
    5. Poisoning Analysis
    6. Rule Verification Report
"""

from __future__ import annotations

import json
import os
from typing import Optional

import requests
import streamlit as st


API = os.environ.get("VERICTI_API", "http://localhost:8000")


st.set_page_config(page_title="VeriCTI-RAG", layout="wide")
st.title("VeriCTI-RAG")
st.caption("Poisoning-Resilient and Evidence-Verified CTI RAG — research prototype")


def _get(path: str, **kw):
    try:
        r = requests.get(f"{API}{path}", timeout=30, **kw)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f"GET {path} failed: {e}")
        return None


def _post(path: str, **kw):
    try:
        r = requests.post(f"{API}{path}", timeout=120, **kw)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f"POST {path} failed: {e}")
        return None


with st.sidebar:
    st.subheader("Documents")
    docs = _get("/documents") or []
    doc_id_map = {f"{d['title']} ({d['doc_id']})": d["doc_id"] for d in docs}
    sel = st.selectbox("Active document", ["(none)"] + list(doc_id_map.keys()))
    active_doc_id: Optional[str] = doc_id_map.get(sel) if sel != "(none)" else None
    st.caption(f"Backend: `{API}`")


tabs = st.tabs([
    "1. Upload Report",
    "2. Extracted CTI",
    "3. Evidence Graph",
    "4. Generated Sigma Rule",
    "5. Poisoning Analysis",
    "6. Rule Verification Report",
])


# Tab 1 ------------------------------------------------------------------
with tabs[0]:
    st.header("Upload CTI Report")
    upload = st.file_uploader("PDF or text report", type=["pdf", "txt", "md"])
    title = st.text_input("Title (optional)")
    source = st.text_input("Source", value="unknown")
    source_type = st.selectbox(
        "Source type",
        ["unknown", "vendor_blog", "government", "academic", "community"],
    )
    if upload is not None and st.button("Ingest uploaded file"):
        files = {"file": (upload.name, upload.getvalue())}
        data = {"title": title, "source": source, "source_type": source_type}
        out = _post("/ingest", files=files, data=data)
        if out:
            st.success(f"Ingested {out['doc_id']}")
            st.json(out)

    st.divider()
    st.subheader("Or paste report text")
    raw = st.text_area("Report text", height=200)
    if st.button("Ingest text") and raw.strip():
        out = _post("/ingest/text", json={
            "text": raw, "title": title or None,
            "source": source, "source_type": source_type,
        })
        if out:
            st.success(f"Ingested {out['doc_id']}")
            st.json(out)


# Tab 2 ------------------------------------------------------------------
with tabs[1]:
    st.header("Extracted CTI")
    if not active_doc_id:
        st.info("Select a document in the sidebar.")
    elif st.button("Run extraction", key="extract-btn"):
        out = _post("/extract", json={"doc_id": active_doc_id})
        if out:
            c1, c2 = st.columns(2)
            with c1:
                st.subheader("STIX entities")
                st.json(out.get("entities", []))
                st.subheader("STIX relationships")
                st.json(out.get("relationships", []))
            with c2:
                st.subheader("ATT&CK mappings")
                st.json(out.get("attack_mappings", []))
                st.subheader("Document")
                st.json(out.get("document"))


# Tab 3 ------------------------------------------------------------------
with tabs[2]:
    st.header("Evidence Graph")
    if not active_doc_id:
        st.info("Select a document in the sidebar.")
    elif st.button("Build graph", key="graph-btn"):
        g = _get(f"/graph/{active_doc_id}")
        if g:
            st.caption(f"{len(g['nodes'])} nodes, {len(g['edges'])} edges")
            try:
                from pyvis.network import Network  # type: ignore

                net = Network(height="600px", width="100%", directed=True,
                              bgcolor="#0e1117", font_color="white")
                colors = {"document": "#4e79a7", "chunk": "#f28e2b",
                          "entity": "#59a14f", "attack": "#e15759",
                          "rule": "#b07aa1"}
                for n in g["nodes"]:
                    label = n.get("name") or n.get("title") or n.get("id")
                    net.add_node(n["id"], label=str(label)[:32],
                                 color=colors.get(n.get("kind"), "#999"))
                for e in g["edges"]:
                    net.add_edge(e["source"], e["target"], label=e.get("rel", ""))
                html = net.generate_html(notebook=False)
                st.components.v1.html(html, height=620, scrolling=False)
            except Exception:
                st.json(g)


# Tab 4 ------------------------------------------------------------------
with tabs[3]:
    st.header("Generated Sigma Rule")
    if not active_doc_id:
        st.info("Select a document in the sidebar.")
    elif st.button("Generate rules", key="rule-btn"):
        out = _post("/generate-rule", json={"doc_id": active_doc_id})
        if out:
            for r in out.get("rules", []):
                st.subheader(f"{r['title']} (`{r['rule_id']}`)")
                st.caption(
                    f"ATT&CK={r['attack_technique']} conf={r['confidence']:.2f} "
                    f"evidence={r['evidence_chunk_ids']}"
                )
                st.code(r["rule_text"], language="yaml")


# Tab 5 ------------------------------------------------------------------
with tabs[4]:
    st.header("Poisoning Analysis")
    raw_for_poison = st.text_area("Paste a clean report to poison", height=200,
                                   key="poison-input")
    attacks = st.multiselect(
        "Attacks",
        ["fake_ioc", "wrong_attack", "false_attribution",
         "prompt_injection", "stale_ioc"],
        default=["fake_ioc", "prompt_injection"],
    )
    if st.button("Run poisoning") and raw_for_poison.strip():
        out = _post("/poison", json={"text": raw_for_poison, "attacks": attacks})
        if out:
            for name, variant in out["variants"].items():
                with st.expander(f"Attack: {name}"):
                    st.code(variant["poisoned_text"], language="markdown")
                    gt = {k: v for k, v in variant.items() if k != "poisoned_text"}
                    st.json(gt)

    st.divider()
    st.subheader("Clean vs poisoned comparison")
    other = st.selectbox(
        "Compare against (poisoned doc)",
        ["(none)"] + list(doc_id_map.keys()),
        key="cmp-other",
    )
    if active_doc_id and other != "(none)" and st.button("Compare"):
        cmp = _post("/evaluate", json={
            "clean_doc_id": active_doc_id,
            "poisoned_doc_id": doc_id_map[other],
        })
        if cmp:
            st.json(cmp)


# Tab 6 ------------------------------------------------------------------
with tabs[5]:
    st.header("Rule Verification Report")
    if not active_doc_id:
        st.info("Select a document in the sidebar.")
    elif st.button("Build analyst report", key="report-btn"):
        rep = _get(f"/report/{active_doc_id}")
        if rep:
            c1, c2, c3 = st.columns(3)
            c1.metric("Final verdict", rep["final_verdict"])
            c2.metric("Final confidence", f"{rep['final_confidence']:.2f}")
            c3.metric("Warnings", len(rep["warnings"]))
            st.subheader("Summary")
            st.write(rep["campaign_summary"])
            st.subheader("Validation results")
            st.json(rep["validation_results"])
            st.subheader("Warnings")
            for w in rep["warnings"]:
                st.warning(w)
            with st.expander("Full report JSON"):
                st.json(rep)
