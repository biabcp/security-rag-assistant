# Security RAG Assistant (Vendor-Neutral, Production-Oriented)

Ingest → Normalize → Redact → Chunk → Embed → Retrieve → Generate → Validate → Audit.

This project is a **security-first Retrieval-Augmented Generation (RAG) assistant** for SOC and incident response workflows. It is designed to be local-first, modular, auditable, and aligned with:

- Modern GenAI architecture patterns
- Responsible AI concepts (NIST AI RMF: Govern, Map, Measure, Manage)
- CISSP-level security engineering and auditability expectations
- Core concepts from NVIDIA Generative AI LLM Associate (RAG lifecycle, prompt design, evaluation)

---

## 1) High-Level Architecture (Text Diagram)

```text
                     +------------------------+
                     |  User CLI / Web UI     |
                     |  (ask, inspect, export)|
                     +-----------+------------+
                                 |
                                 v
+------------------+   +---------+----------+    +--------------------------+
| Raw Log Sources  +-->+ Ingestion Service   +--->+ Immutable Raw Storage     |
| Sysmon, EDR, IAM |   | parse + schema map  |    | data/raw/*.jsonl          |
+------------------+   +---------+----------+    +--------------------------+
                                 |
                                 v
                     +-----------+------------+
                     | Preprocess/Enrichment  |
                     | redact, classify IP,   |
                     | normalize event types  |
                     +-----------+------------+
                                 |
                                 v
                     +-----------+------------+
                     | Chunk + Embedding      |
                     | event/session chunks   |
                     +-----------+------------+
                                 |
                                 v
                     +-----------+------------+
                     | Vector Index + Metadata|
                     | FAISS + JSONL metadata |
                     +-----------+------------+
                                 |
                                 v
                     +-----------+------------+
                     | Retrieval Orchestrator |
                     | semantic + filters     |
                     +-----------+------------+
                                 |
                                 v
                     +-----------+------------+
                     | RAG Generator Layer    |
                     | grounded prompt policy |
                     +-----------+------------+
                                 |
                                 v
                     +-----------+------------+
                     | Output Guardrails      |
                     | PII filter, evidence   |
                     | check, confidence tag  |
                     +-----------+------------+
                                 |
                                 v
                     +-----------+------------+
                     | Audit Log (critical)   |
                     | query, docs, answer    |
                     +------------------------+
```

---

## 2) Suggested Repository Structure

```text
security-rag-assistant/
├── src/security_rag/
│   ├── ingest.py           # ingestion + normalization write
│   ├── preprocess.py       # redaction + parsing + enrichment
│   ├── vector_store.py     # FAISS + metadata + filters
│   ├── rag.py              # retrieval + grounded response policy
│   ├── audit.py            # append-only interaction logging
│   ├── cli.py              # CLI interface (ingest/index/ask)
│   └── schemas.py          # canonical event model
├── data/
│   ├── raw/                # immutable raw logs (append-only)
│   ├── processed/          # normalized logs
│   ├── index/              # vector index + metadata
│   └── audit/              # interaction audit trails
├── eval/evaluate.py        # retrieval/answer quality checks
├── tests/                  # unit + integration tests
├── pyproject.toml
└── README.md
```

---

## 3) Phased Implementation Plan

### Phase 0 — Governance Baseline (NIST AI RMF: Govern)
- Define intended use: analyst assistant, not autonomous responder.
- Define unacceptable use: automated blocking without human validation.
- Create decision-rights and ownership (SOC lead, AI owner, security owner).
- Enable audit retention policy and privacy policy.

### Phase 1 — Data Pipeline
- Ingest JSON/JSONL logs into `data/raw` without mutation.
- Normalize into canonical schema with stable event IDs.
- Preserve chain-of-custody references to original records.

### Phase 2 — Preprocessing & Security
- Redact secrets and sensitive fields.
- Enrich with timestamp standardization, IP class, event tags.
- Implement chunking strategy:
  - **Event-based** (default): one event per chunk.
  - **Session-based** (optional): aggregate by user/host/time window.

### Phase 3 — Embeddings & Retrieval
- Convert chunks to vectors (local deterministic embedding baseline).
- Store vectors in FAISS with metadata for filters (host, severity, time).
- Retrieve by semantic similarity + metadata constraints.

### Phase 4 — RAG and Guardrails
- Use system prompt enforcing “no fabrication” policy.
- Require evidence citation (event IDs).
- Add output checks:
  - if no evidence: `Insufficient evidence.`
  - redact accidental sensitive output
  - confidence annotation

### Phase 5 — Evaluation & Hardening
- Precision@k for retrieval relevance.
- Hallucination heuristic for uncited event IDs.
- Query regression suite with expected evidence.
- Security tests: prompt injection attempts, sensitive-output tests.

### Phase 6 — Deployment
- Containerize services separately (ingestion, retrieval, generation).
- Keep interfaces local/open (CLI/REST), no cloud lock-in.
- Add CI checks, signed images, vulnerability scanning.

---

## 4) Key Code Paths

### Ingestion
```bash
security-rag ingest data/raw/sample_logs.jsonl
```

### Build index
```bash
security-rag index
```

### Ask a question
```bash
security-rag ask "Show suspicious login activity in the last 24 hours" --hours 24
```

### Audit output
Every query appends to:
- `data/audit/interactions.jsonl`

Each audit record includes:
- timestamp
- original query
- retrieved document IDs
- generated response

---

## 5) Prompt Policy (Grounded Security Analyst)

Use this system prompt structure:

```text
You are a senior SOC analyst assistant.
Use only retrieved evidence; never invent events.
Separate FACTS and INTERPRETATION.
If evidence is weak or missing, output exactly: Insufficient evidence.
Never reveal secrets or PII.
Always cite event_id values used as evidence.
```

---

## 6) Example Queries

- “Show suspicious login activity in the last 24 hours.”
- “Summarize potential security incidents for host srv-fin-02.”
- “Explain why event 2fa1ab34cd56ef78 may be malicious.”
- “List high-severity PowerShell events from today.”

---

## 7) Evaluation Strategy

### Retrieval metrics
- Precision@k (k=3,5,10)
- Optional Recall@k with labeled datasets

### Generation quality
- Evidence-grounded answer rate
- Analyst rubric (correct, partially correct, unsupported)

### Hallucination control
- Flag answers containing synthetic event IDs not in retrieved docs.
- Fail closed on no-evidence scenarios.

---

## 8) Security & Governance Controls (Production)

- **Data security:** encryption at rest/in transit, strict RBAC, key rotation
- **Auditability:** append-only logs, immutable raw store, change management
- **Privacy:** PII minimization, redaction before indexing
- **Model risk:** documented limitations, human-in-the-loop for actions
- **Threat model:** prompt injection, data poisoning, retrieval abuse, exfiltration
- **Compliance mapping:** SOC2/ISO27001 controls, NIST AI RMF lifecycle evidence

---

## 9) Local Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
security-rag --help
```

---

## 10) Optional Enhancements

- Rule/statistical anomaly scoring module
- Benign vs suspicious incident classifier
- Minimal dashboard (Streamlit/FastAPI)
- Pluggable LLM provider adapter (local + cloud) while preserving same interfaces

