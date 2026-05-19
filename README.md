# VeriCTI-RAG (Prototype)

**Poisoning-Resilient and Evidence-Verified Cyber Threat Intelligence RAG for Detection Rule Generation**

This is the working research prototype implementing the system described in
the top-level `../README.md`. It is defensive and research-oriented: it helps
analysts *verify* CTI-derived detection logic. It does **not** automate any
real-world malicious activity.

---

## 📄 Report & Results

| Document | Contents |
|----------|----------|
| **[REPORT.md](REPORT.md)** | Full academic report: abstract, threat model, system design, experiments, quantitative results, limitations, future work |
| `demo_output.txt` | Complete output of `python run_demo.py` (analyst report + clean-vs-poisoned comparison) |
| `test_output.txt` | `pytest -q` — 15 passed in 0.34s |
| `eval_output.txt` | Ground-truth precision/recall/F1 evaluation (Entity F1=0.88, Technique F1=0.92) |

---

## 🚀 Quick Start

### Option A: Minimal install (tests + CLI demo only)

```bash
cd vericti-rag
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-min.txt

# Run all 15 unit tests
pytest -q

# Run the end-to-end demo (ingests sample report → extraction → rules → verification → poisoning)
python run_demo.py

# Run ground-truth precision/recall evaluation
python -c "import sys; sys.path.insert(0,'.'); from app.evaluation.ground_truth_eval import main; main()"
```

> **No API keys, no model downloads, no internet access required.**  
> The minimal install uses only BM25 retrieval and rule-based extraction.

### Option B: Full stack (backend + UI + vector DB + embeddings)

```bash
pip install -r requirements-full.txt

# Start the FastAPI backend
uvicorn app.main:app --reload --port 8000

# In a separate terminal, start the Streamlit frontend
streamlit run frontend/streamlit_app.py
```

### Option C: Legacy single requirements file

```bash
pip install -r requirements.txt
```

---

## ⚙️ Configuration

All settings are via environment variables (see `app/core/config.py`):

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
pytest -q                    # 15 tests across 5 modules
pytest -v                    # verbose output
pytest tests/test_sigma.py   # run a specific test module
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

See `REPORT.md` § 9 for a complete annotated file inventory.

```
vericti-rag/
├── app/                     # Backend: API, pipeline, modules
│   ├── main.py              # FastAPI entrypoint
│   ├── services/pipeline.py # End-to-end orchestration
│   ├── core/                # Config, DB, schemas, LLM
│   ├── ingestion/           # Text/PDF loading, chunking
│   ├── retrieval/           # BM25 + vector hybrid retrieval
│   ├── extraction/          # IOC, STIX, ATT&CK extraction
│   ├── graph/               # Evidence graph + consistency
│   ├── rules/               # Sigma generation + validation + execution
│   ├── defense/             # Evidence verification + confidence scoring
│   ├── attacks/             # 5 poisoning attack modules
│   └── evaluation/          # Metrics, experiments, evaluation harness
├── data/                    # Reports, logs, ground truth, DB
├── frontend/                # Streamlit dashboard
├── prompts/                 # LLM prompt templates
├── tests/                   # 15 unit tests
├── requirements-min.txt     # Minimal deps (tests + demo)
├── requirements-full.txt    # Full deps (UI + vector + embeddings)
├── requirements.txt         # Legacy combined deps
├── run_demo.py              # CLI demo script
├── REPORT.md                # Academic project report
└── README.md                # This file
```
