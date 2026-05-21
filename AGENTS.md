# AGENTS.md

## Cursor Cloud specific instructions

### Overview

This is a **Security RAG Assistant** — a local-first CLI tool for SOC analysts. It ingests security logs, normalizes/redacts them, builds a FAISS vector index, and answers natural-language queries grounded in retrieved evidence. No external services or API keys are needed for the core workflow.

### Running the application

```bash
export PATH="/home/ubuntu/.local/bin:$PATH"
security-rag ingest data/raw/sample_logs.jsonl   # Ingest + normalize logs
security-rag index                                # Build FAISS vector index
security-rag ask "Show suspicious login activity" # Query the RAG system
```

### Testing

```bash
pytest tests/ -v      # Unit tests
ruff check src/ tests/ # Lint
```

### Key caveats

- The `security-rag` CLI is installed to `/home/ubuntu/.local/bin` — ensure this is on `PATH`.
- The `data/processed/`, `data/index/`, and `data/audit/` directories are created at runtime by the CLI commands. They are gitignored and do not need to exist prior to running.
- No external API keys are needed for the default workflow. The LLM optional dependency (`openai`) is installed but the system uses a rule-based answer generator by default.
- Python 3.11+ is required (3.12 works fine).
- `pytest` and `ruff` are dev dependencies not listed in `pyproject.toml`; they are installed separately.
