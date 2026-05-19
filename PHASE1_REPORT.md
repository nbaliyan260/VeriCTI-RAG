# VeriCTI-RAG: Poisoning-Resilient and Evidence-Verified Cyber Threat Intelligence RAG for Detection Rule Generation

**Phase 1 Report — Research Prototype**

Author: Nazish Baliyan  
Date: May 2026  
Status: Phase 1 MVP (prototype, not final paper)

---

## Abstract

Cyber threat intelligence (CTI) reports are the primary input for security operations, yet transforming unstructured reports into actionable detection logic remains manual, slow, and error-prone. Large language model (LLM) based retrieval-augmented generation (RAG) systems promise automation, but introduce a critical trust gap: poisoned, stale, or contradictory CTI in the retrieval corpus can cause the system to generate fake indicators of compromise (IOCs), incorrect MITRE ATT&CK mappings, and unsafe detection rules. We present **VeriCTI-RAG**, a research prototype that addresses this gap through evidence-verified, poisoning-resilient CTI processing. The system ingests unstructured CTI reports, extracts STIX-style entities and ATT&CK technique mappings with evidence provenance, generates Sigma detection rules, and verifies every output through syntax validation, semantic evidence grounding, graph-based consistency checks, and log-based execution testing. We introduce a controlled CTI poisoning benchmark covering six attack types (fake IOC injection, false attribution, wrong ATT&CK mapping, prompt injection, stale IOCs, and detection-rule corruption). Phase 1 evaluation on sample reports demonstrates 0.88 macro-F1 on entity extraction, 0.92 macro-F1 on technique mapping, 100% true-positive rate and 0% false-positive rate on generated Sigma rules, and correct detection of poisoning artefacts.

---

## 1. Motivation

### 1.1 Industry Relevance

Security Operations Center (SOC) teams process an increasing volume of CTI reports — vendor blogs, government advisories, community feeds, and academic publications. The manual workflow is:

1. Read a CTI report.
2. Extract IOCs (IPs, domains, hashes, URLs).
3. Map observed behaviors to MITRE ATT&CK techniques.
4. Write detection rules (Sigma, YARA, Snort).
5. Test rules against logs to verify correctness.
6. Deploy rules to SIEM/EDR.

This workflow is expensive (~4-8 hours per high-quality report), error-prone (manual ATT&CK mapping has ~30% disagreement between analysts), and does not scale.

### 1.2 The RAG Opportunity and Risk

LLM-based RAG systems can automate steps 1-4, reducing processing time from hours to seconds. However, the retrieved CTI corpus is treated as trusted ground truth. If an adversary poisons the corpus (or if reports are simply outdated or contradictory), the RAG system will:

- Generate **fake IOCs** that waste analyst time or cause alert fatigue.
- Produce **wrong ATT&CK mappings** that create detection blind spots.
- Emit **unsafe Sigma rules** with high false-positive rates.
- **Suppress warnings** through prompt injection.

### 1.3 Research Gap

Existing work has addressed CTI extraction (AZERG, 2025) and RAG poisoning (PoisonedRAG, 2024; RAGRank, 2025) separately, but no system combines:

1. End-to-end CTI-to-rule generation
2. Evidence provenance for every output
3. Poisoning-resilient verification
4. Log-based rule execution testing

VeriCTI-RAG fills this gap.

---

## 2. Threat Model

We assume an adversary who can inject or modify CTI reports in the retrieval corpus before the system processes them. The adversary's goal is to corrupt downstream outputs (entities, mappings, rules) without being detected.

### 2.1 Attack Taxonomy

| ID | Attack | Module | Adversary Goal |
|----|--------|--------|----------------|
| A | Fake IOC injection | `poison_ioc.py` | Inject fabricated domains/IPs/hashes |
| B | False attribution | `poison_false_attribution.py` | Swap threat-actor names (e.g., FIN7 → APT29) |
| C | Wrong ATT&CK mapping | `poison_attack_mapping.py` | Replace correct technique IDs with wrong ones |
| D | Detection-rule corruption | (via C) | Indirectly cause wrong Sigma rule fields |
| E | Prompt injection | `poison_prompt_injection.py` | Insert adversarial LLM instructions |
| F | Stale IOC injection | `poison_stale_ioc.py` | Add indicators with old "last seen" dates |

### 2.2 Defense Mechanisms

| Defense | Module | How It Works |
|---------|--------|-------------|
| Evidence provenance | `provenance_checker.py` | Every entity/rule must reference ≥1 evidence chunk |
| Evidence support scoring | `evidence_verifier.py` | Lexical verification that cited text supports the claim |
| Prompt injection detection | `evidence_verifier.py` | Regex patterns for adversarial instructions; 0.3× penalty |
| Source trust scoring | `trust_scorer.py` | Source-type-based trust (government=0.9, unknown=0.4) |
| Freshness scoring | `freshness_scorer.py` | Exponential decay based on publication date |
| Graph consistency | `consistency_checker.py` | Single-source warnings, unsupported entity detection |
| Contradiction detection | `contradiction_detector.py` | Multi-actor attribution, benign-vs-malicious IOC conflicts |
| Rule syntax validation | `sigma_validator.py` | Structural checks + pySigma schema validation |
| Rule semantic verification | `evidence_verifier.py` | ATT&CK keyword patterns verified in evidence chunks |
| Rule log execution | `rule_executor.py` | Execute rules against malicious + benign JSONL logs |
| Final confidence scoring | `final_confidence.py` | Weighted combination: evidence(0.35) + trust(0.15) + freshness(0.15) + graph(0.15) + validation(0.20) |

---

## 3. System Architecture

### 3.1 Pipeline Overview

```
CTI Report (text/PDF)
    │
    ▼
┌─────────────────────┐
│  Ingestion Layer     │   chunker.py, text_loader.py, pdf_loader.py
│  → metadata + chunks │   metadata_extractor.py
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Retrieval Layer     │   bm25_retriever.py, vector_retriever.py
│  → relevant chunks   │   hybrid_retriever.py (α-blended)
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Extraction Layer    │   ioc_extractor.py (regex + defang)
│  → STIX entities     │   stix_extractor.py (gazetteer)
│  → ATT&CK mappings   │   attack_mapper.py (keyword)
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Evidence Graph      │   graph_builder.py (NetworkX MultiDiGraph)
│  → consistency       │   consistency_checker.py
│  → contradictions    │   contradiction_detector.py
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Rule Generation     │   sigma_generator.py (template-driven)
│  → Sigma YAML rules  │   6 technique templates
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Verification Layer  │   sigma_validator.py (syntax)
│  → syntax check      │   evidence_verifier.py (semantic)
│  → semantic check    │   rule_executor.py (log execution)
│  → log execution     │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Analyst Report      │   final_confidence.py (weighted scoring)
│  → confidence score   │   report_generator.py (markdown)
│  → verdict + warnings │
└─────────────────────┘
```

### 3.2 Key Design Decisions

1. **Deterministic-first approach**: Phase 1 uses rule-based extraction and template-driven generation for reproducibility and auditability. LLM augmentation is deferred to Phase 2.

2. **Evidence as first-class citizen**: The Pydantic schema enforces that no entity, relationship, ATT&CK mapping, or rule can exist without at least one `evidence_chunk_id`. Violations raise `ValueError` at construction time.

3. **Multi-signal confidence**: The final confidence score is not a single metric but a weighted combination of evidence support, source trust, freshness, graph consistency, and rule validation — reflecting real-world analyst judgment.

4. **Offline by default**: The entire pipeline runs without API keys, model downloads, or internet access when using the `mock` LLM provider.

---

## 4. Implemented Modules

### 4.1 Ingestion (`app/ingestion/`)
- `text_loader.py`: Loads text from bytes, strings, or file paths.
- `pdf_loader.py`: Extracts text from PDF files using pypdf.
- `chunker.py`: Fixed-size chunking (500 chars, 100 overlap) with char-level offset tracking.
- `metadata_extractor.py`: Extracts publication date and title from report headers.

### 4.2 Retrieval (`app/retrieval/`)
- `bm25_retriever.py`: BM25 retrieval with fallback scoring for tiny corpora.
- `vector_retriever.py`: ChromaDB vector store with sentence-transformers (optional).
- `hybrid_retriever.py`: Configurable α-blended hybrid of BM25 + vector.

### 4.3 Extraction (`app/extraction/`)
- `ioc_extractor.py`: Regex IOC extraction (IPv4, domains, URLs, MD5/SHA1/SHA256, CVE) with defang normalization, TLD validation, and chunk-boundary guards.
- `stix_extractor.py`: Gazetteer-based STIX entity matching (malware families, threat actors, tools) + relationship extraction from verb patterns.
- `attack_mapper.py`: Keyword-driven ATT&CK technique mapping for 11 techniques across 6 tactics.

### 4.4 Evidence Graph (`app/graph/`)
- `graph_builder.py`: NetworkX MultiDiGraph with nodes for documents, chunks, entities, techniques, and rules. Edges encode `contains`, `supports`, and `detects` relationships.
- `consistency_checker.py`: Flags single-source entities, unsupported entities, contradictory attributions, and rules detecting unsupported techniques.
- `contradiction_detector.py`: Detects multi-actor malware attribution and benign-vs-malicious IOC conflicts.

### 4.5 Rules (`app/rules/`)
- `sigma_generator.py`: Template-driven Sigma YAML generation for T1059.001, T1059.003, T1218.010, T1218.011, T1105, T1047.
- `sigma_validator.py`: Structural validation (required keys, detection structure) + pySigma schema validation.
- `rule_executor.py`: Executes Sigma rules against per-technique JSONL log files. Supports field modifiers: `endswith`, `contains`, `startswith`, exact match.

### 4.6 Defense (`app/defense/`)
- `evidence_verifier.py`: Lexical evidence support scoring (0-1) with prompt-injection pattern detection and 0.3× penalty for injection-bearing chunks.
- `freshness_scorer.py`: Exponential decay freshness score based on publication date (configurable half-life).
- `trust_scorer.py`: Source-type-based trust initialization (government=0.9, vendor_blog=0.7, academic=0.8, community=0.5, unknown=0.4).
- `provenance_checker.py`: Verifies that every entity/relationship/mapping/rule references existing chunks.
- `final_confidence.py`: Weighted multi-signal confidence scoring + verdict assignment.

### 4.7 Attacks (`app/attacks/`)
- `poison_ioc.py`: Injects fabricated domains, IPs, and hashes with ground-truth annotations.
- `poison_false_attribution.py`: Swaps threat-actor names while preserving surrounding text.
- `poison_attack_mapping.py`: Replaces correct technique IDs with plausible wrong ones.
- `poison_prompt_injection.py`: Inserts adversarial LLM instructions.
- `poison_stale_ioc.py`: Adds indicators with old "last seen" dates.

### 4.8 Evaluation (`app/evaluation/`)
- `metrics.py`: Precision, recall, F1, evidence faithfulness, FPR/TPR.
- `run_poisoning_experiment.py`: Clean-vs-poisoned comparison harness.
- `ground_truth_eval.py`: Evaluation against annotated ground-truth JSON files.
- `report_generator.py`: Markdown-formatted analyst report.

---

## 5. Phase 1 Achievements

| Achievement | Metric |
|------------|--------|
| Entity extraction (macro-F1) | **0.88** |
| Technique mapping (macro-F1) | **0.92** |
| Entity recall | **1.00** |
| Technique recall | **1.00** |
| Sigma rules generated | 4 per report |
| Rule syntax valid | 100% |
| Rule semantic valid | 100% |
| Rule TPR (malicious logs) | **1.00** |
| Rule FPR (benign logs) | **0.00** |
| Poisoning detection | ✅ Newly introduced IOCs flagged |
| Prompt injection detection | ✅ Patterns matched and penalized |
| Evidence provenance | ✅ Every output linked to source chunks |
| Unit tests | 27 tests, all passing |
| Offline operation | ✅ No API keys or internet required |

---

## 6. Demo Walkthrough

Run the professor demo:

```bash
cd vericti-rag
source .venv/bin/activate
make professor-demo
```

### Step-by-step output

1. **Ingest**: Loads `demo_clean_cti_report.txt` (ShadowLoader campaign, government source, trust=0.9)
2. **Extract**: 8 STIX entities (3 IOCs, 1 malware, 1 threat actor, 3 tools) + 7 ATT&CK mappings
3. **Map**: T1059.001, T1140, T1218.011, T1071.001, T1105, T1047, T1003
4. **Generate**: 4 Sigma rules (PowerShell, Rundll32, Tool Transfer, WMI)
5. **Verify**: All rules pass syntax + semantic + log execution (0% FPR)
6. **Evidence**: Every entity linked to specific chunk + text snippet
7. **Poison**: Poisoned report introduces 3 fake IOCs; system flags them
8. **Report**: Verdict = verified_with_caution, Confidence = 0.85, 8 warnings

---

## 7. Current Evaluation

### 7.1 Entity Extraction Accuracy

| Report | Precision | Recall | F1 |
|--------|-----------|--------|-----|
| APT Report | 0.70 | 1.00 | 0.82 |
| Ransomware Report | 0.88 | 1.00 | 0.93 |
| **Macro Average** | **0.79** | **1.00** | **0.88** |

### 7.2 Technique Mapping Accuracy

| Report | Precision | Recall | F1 |
|--------|-----------|--------|-----|
| APT Report | 0.71 | 1.00 | 0.83 |
| Ransomware Report | 1.00 | 1.00 | 1.00 |
| **Macro Average** | **0.86** | **1.00** | **0.92** |

### 7.3 Rule Verification

| Rule | TPR | FPR | Verdict |
|------|-----|-----|---------|
| PowerShell (T1059.001) | 5/5 = 1.00 | 0/10 = 0.00 | verified |
| Rundll32 (T1218.011) | 2/2 = 1.00 | 0/2 = 0.00 | verified |
| Tool Transfer (T1105) | 3/3 = 1.00 | 0/3 = 0.00 | verified |
| WMI (T1047) | 2/2 = 1.00 | 0/2 = 0.00 | verified |

### 7.4 Poisoning Detection

| Metric | Clean | Poisoned |
|--------|-------|----------|
| Entities | 8–10 | 12–13 |
| Evidence faithfulness | 1.00 | 0.93 |
| Newly introduced IOCs | — | 1–3 detected |
| Prompt injection | — | Patterns matched |

---

## 8. Limitations

1. **Rule-based extraction**: The MVP uses gazetteers and regex, which limits recall on novel entities. LLM augmentation is needed for free-form extraction.
2. **Small evaluation corpus**: Results are on 2-3 sample reports. Generalization requires larger datasets (AZERG: 141 reports).
3. **Limited Sigma execution**: The log executor supports a subset of Sigma modifiers. Full pySigma backend conversion is not implemented.
4. **Single-report analysis**: Cross-report corroboration is implemented in the graph but not extensively tested.
5. **No real-world deployment**: This is a research prototype, not a production SOC tool.
6. **Freshness scoring**: Implemented but not yet integrated into the poisoning detection feedback loop.

---

## 9. Phase 2 Plan

### 9.1 Research Extensions

| Task | Timeline | Expected Impact |
|------|----------|-----------------|
| AZERG dataset evaluation | Month 1 | Strong quantitative results on established benchmark |
| LLM-augmented extraction | Month 1-2 | Higher recall for novel entities |
| Multi-seed poisoning evaluation | Month 2 | Statistical significance for defense metrics |
| Cross-report corroboration | Month 2-3 | Multi-source confidence boosting |
| Real log validation (Mordor) | Month 3 | Rule quality on real-world event data |
| User study with SOC analysts | Month 3-4 | Human evaluation of verification value |
| YARA rule generation | Month 4 | File-based indicator coverage |

### 9.2 Target Venues

| Venue | Fit | Deadline (typical) |
|-------|-----|---------------------|
| USENIX Security | Strong (systems security) | February / September |
| ACM CCS | Strong (applied security) | January / May |
| NDSS | Good (network/distributed) | May / July |
| AISec Workshop | Good (AI + security) | Co-located with CCS |
| DIMVA | Good (intrusion detection) | February |

---

## 10. Expected A*/Top-Security Contribution

### What makes this publishable

1. **Novel combination**: No existing system combines CTI-to-rule generation + evidence provenance + poisoning resilience + log-based verification.
2. **Practical threat model**: The 6 attack types reflect real-world CTI supply chain risks.
3. **Quantitative defense evaluation**: Clean-vs-poisoned comparison with measurable metrics (faithfulness, confidence, newly introduced IOCs).
4. **Reproducibility**: The entire system runs offline with deterministic, rule-based extraction — no API key dependencies.
5. **Industry relevance**: Directly addresses SOC analyst workflows and CTI trust gaps.

### What is needed for A* (Phase 2)

1. Evaluation on a **large, established dataset** (AZERG or comparable).
2. **Comparison against baselines** (unverified RAG, AZERG extraction, SIGMERGE rule generation).
3. **Statistical significance** across multiple runs/seeds.
4. **User study** with practicing SOC analysts.
5. **LLM integration** to demonstrate that the verification layer works with both deterministic and non-deterministic extraction.
