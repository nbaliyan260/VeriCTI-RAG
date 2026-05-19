# VeriCTI-RAG (Prototype)

**Poisoning-Resilient and Evidence-Verified Cyber Threat Intelligence RAG for Detection Rule Generation**

This is the working research prototype implementing the system described in
the top-level `../README.md`. It is defensive and research-oriented: it helps
analysts *verify* CTI-derived detection logic. It does **not** automate any
real-world malicious activity.

---

## 📄 Reports & Documentation

| Document | Contents |
|----------|----------|
| **[PROFESSOR_DEMO.md](PROFESSOR_DEMO.md)** | 2-minute summary, demo guide, discussion questions for professor meeting |
| **[PHASE1_REPORT.md](PHASE1_REPORT.md)** | Academic-style Phase 1 report: abstract, motivation, architecture, evaluation, Phase 2 plan |
| **[REPORT.md](REPORT.md)** | Full technical report: threat model, system design, experiments, quantitative results |
| `demo_summary.json` | Structured JSON output from the professor demo |
| `demo_output.txt` | Complete output of `python run_demo.py` |
| `test_output.txt` | `pytest -q` — 27 tests passing |
| `eval_output.txt` | Ground-truth precision/recall/F1 evaluation (Entity F1=0.88, Technique F1=0.92) |

---

## 🎓 Professor Demo

### Why this demo exists

The professor demo is a **polished, 8-step walkthrough** designed for a thesis proposal meeting or research advisor review. It shows the complete VeriCTI-RAG pipeline running end-to-end on a single CTI report, then demonstrates how a poisoned report corrupts the output and how the system detects the corruption.

### How to run it

```bash
cd vericti-rag
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-min.txt

make professor-demo
# or: python run_professor_demo.py --json
```

> **Runs fully offline.** No API keys, no model downloads, no internet.

### What to show during the meeting

1. **Steps 1-5**: "This is what the system does — ingest, extract, map, generate, verify."
2. **Step 6**: "Every output is linked to specific evidence text — this is what makes it different from a normal RAG."
3. **Step 7**: "Here's what happens when the CTI corpus is poisoned — new fake IOCs appear, and the system flags them."
4. **Step 8**: "The final analyst report gives a confidence score and warnings, so the analyst can make an informed decision."

### Expected output highlights

| Step | Key Output |
|------|-----------|
| Ingest | doc_id, title, trust_score=0.9 |
| Extract | 8 entities with evidence chunk links |
| ATT&CK | 7 technique mappings (T1059.001, T1105, etc.) |
| Sigma | 4 rules, all verified, 0% FPR |
| Evidence | Every entity → chunk → source text snippet |
| Poisoning | 3 newly introduced fake IOCs detected |
| Report | Verdict=verified_with_caution, Confidence=0.85 |

### What is implemented (Phase 1)

- ✅ Full pipeline: ingest → extract → map → generate → verify
- ✅ 5 poisoning attack types with ground-truth annotations
- ✅ Evidence provenance for every output
- ✅ 10 defense mechanisms (trust, freshness, provenance, injection detection, etc.)
- ✅ 27 unit tests, all passing
- ✅ FastAPI backend + Streamlit dashboard

### What is planned (Phase 2)

- AZERG dataset evaluation (141 reports, 4,011 entities)
- LLM-augmented extraction (GPT-4o / Claude)
- Cross-report corroboration
- Real log validation (Mordor, Atomic Red Team)
- User study with SOC analysts

---

## 🚀 Quick Start

### Option A: Minimal install (tests + demo only)

```bash
cd vericti-rag
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-min.txt

# Run all tests
make test

# Run the professor demo
make professor-demo

# Run the standard demo
make demo
```

> **No API keys, no model downloads, no internet access required.**  
> The minimal install uses only BM25 retrieval and rule-based extraction.

### Option B: Full stack (backend + UI + vector DB + embeddings)

```bash
pip install -r requirements-full.txt

make api     # terminal 1: FastAPI on port 8000
make ui      # terminal 2: Streamlit frontend
```

### Option C: Legacy single requirements file

```bash
pip install -r requirements.txt
```

---

## ⚙️ Configuration

All settings are via environment variables (see `.env.example` and `app/core/config.py`):

| Variable | Default | Description |
|----------|---------|-------------|
| `VERICTI_DATA_DIR` | `./data` | Data directory (reports, logs, DB) |
| `VERICTI_DB_PATH` | `./data/vericti.db` | SQLite database path |
| `VERICTI_CHROMA_DIR` | `./data/chroma` | ChromaDB persistence directory |
| `VERICTI_LLM_PROVIDER` | `mock` | LLM provider: `mock`, `openai`, `anthropic` |
| `VERICTI_LLM_MODEL` | `gpt-4o-mini` | LLM model name (when using openai/anthropic) |
| `OPENAI_API_KEY` | — | OpenAI API key (optional) |
| `ANTHROPIC_API_KEY` | — | Anthropic API key (optional) |

The default `mock` LLM provider performs deterministic, rule-based extraction
so the entire pipeline runs **offline** with no API keys.

---

## 🧪 Tests

```bash
make test                            # all 27 tests
pytest -v                            # verbose output
pytest tests/test_professor_demo.py  # professor demo tests (12 tests)
pytest tests/test_sigma.py           # Sigma generation tests
```

---

## 📡 API Endpoints

The FastAPI backend exposes:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/` | Health check |
| `GET`  | `/documents` | List ingested documents |
| `POST` | `/ingest` | Upload file or text for ingestion |
| `POST` | `/ingest/text` | Ingest inline text (JSON body) |
| `POST` | `/extract` | Extract STIX entities + ATT&CK mappings |
| `POST` | `/generate-rule` | Generate Sigma rules from a document |
| `POST` | `/verify-rule` | Verify a Sigma rule (syntax + semantic + logs) |
| `POST` | `/poison` | Apply poisoning attacks to text |
| `POST` | `/evaluate` | Compare clean vs poisoned documents |
| `GET`  | `/graph/{doc_id}` | Get evidence graph for a document |
| `GET`  | `/report/{doc_id}` | Build full analyst report |

---

## 🎛️ Streamlit Dashboard

The frontend has 6 tabs:

1. **Upload Report** — Ingest PDF/text files or paste report text
2. **Extracted CTI** — View STIX entities, relationships, ATT&CK mappings
3. **Evidence Graph** — Interactive PyVis network visualization
4. **Generated Sigma Rule** — View generated rules with evidence links
5. **Poisoning Analysis** — Apply attacks, compare clean vs poisoned
6. **Rule Verification Report** — Full analyst verdict with confidence and warnings

---

## 📁 Project Layout

```
vericti-rag/
├── app/                          # Backend: API, pipeline, modules
│   ├── main.py                   # FastAPI entrypoint
│   ├── services/pipeline.py      # End-to-end orchestration
│   ├── core/                     # Config, DB, schemas, LLM
│   ├── ingestion/                # Text/PDF loading, chunking
│   ├── retrieval/                # BM25 + vector hybrid retrieval
│   ├── extraction/               # IOC, STIX, ATT&CK extraction
│   ├── graph/                    # Evidence graph + consistency
│   ├── rules/                    # Sigma generation + validation + execution
│   ├── defense/                  # Evidence verification + confidence scoring
│   ├── attacks/                  # 5 poisoning attack modules
│   └── evaluation/               # Metrics, experiments, evaluation harness
├── data/
│   ├── raw_reports/              # Clean CTI reports (incl. demo report)
│   ├── poisoned_reports/         # Poisoned CTI reports (incl. demo report)
│   ├── ground_truth/             # Ground-truth annotation JSON
│   ├── logs_malicious/           # Per-technique malicious JSONL logs
│   └── logs_benign/              # Per-technique benign JSONL logs
├── frontend/                     # Streamlit 6-tab dashboard
├── prompts/                      # LLM prompt templates
├── tests/                        # 27 unit tests (6 modules)
├── Makefile                      # make test / demo / professor-demo / api / ui
├── .env.example                  # Configuration template
├── requirements-min.txt          # Minimal deps (tests + demo)
├── requirements-full.txt         # Full deps (UI + vector + embeddings)
├── requirements.txt              # Legacy combined deps
├── run_demo.py                   # Standard CLI demo
├── run_professor_demo.py         # Professor demo (Phase 1)
├── demo_summary.json             # Structured demo output
├── PROFESSOR_DEMO.md             # Professor meeting guide
├── PHASE1_REPORT.md              # Academic Phase 1 report
├── REPORT.md                     # Full technical report
└── README.md                     # This file
```
