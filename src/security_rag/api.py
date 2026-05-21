"""FastAPI REST API for the Security RAG Assistant."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .ingest import ingest_csv, ingest_directory, ingest_jsonl
from .llm import get_llm_provider
from .rag import RAGAssistant, build_index_from_normalized
from .vector_store import LocalVectorStore

app = FastAPI(title="Security RAG API", version="0.1.0")

DATA_DIR = Path("data")
NORMALIZED_PATH = DATA_DIR / "processed" / "normalized.jsonl"
INDEX_PATH = DATA_DIR / "index"
AUDIT_PATH = DATA_DIR / "audit" / "interactions.jsonl"


class IngestRequest(BaseModel):
    raw_path: str
    append: bool = False


class IngestResponse(BaseModel):
    events_ingested: int
    normalized_path: str


class IndexRequest(BaseModel):
    backend: str = "hashing"
    strategy: str = "event"
    window_minutes: int = 5


class IndexResponse(BaseModel):
    chunks_indexed: int


class AskRequest(BaseModel):
    query: str
    host: str | None = None
    severity: str | None = None
    hours: int | None = None
    k: int = 5
    hybrid_alpha: float = 1.0
    llm_provider: str = "rule"


class AskResponse(BaseModel):
    query: str
    evidence: list[dict[str, Any]]
    answer: str


class StatusResponse(BaseModel):
    events_ingested: int
    events_indexed: int
    index_exists: bool
    last_event_time: str
    audit_entries: int


@app.post("/ingest", response_model=IngestResponse)
def api_ingest(request: IngestRequest) -> IngestResponse:
    """Ingest log files."""
    raw_path = Path(request.raw_path)
    if not raw_path.exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {request.raw_path}")

    if raw_path.is_dir():
        n = ingest_directory(raw_path, NORMALIZED_PATH, append=request.append)
    elif raw_path.suffix == ".csv":
        n = ingest_csv(raw_path, NORMALIZED_PATH, append=request.append)
    else:
        n = ingest_jsonl(raw_path, NORMALIZED_PATH, append=request.append)

    return IngestResponse(events_ingested=n, normalized_path=str(NORMALIZED_PATH))


@app.post("/index", response_model=IndexResponse)
def api_index(request: IndexRequest) -> IndexResponse:
    """Build vector index."""
    if not NORMALIZED_PATH.exists():
        raise HTTPException(status_code=400, detail="No normalized data. Run /ingest first.")

    n = build_index_from_normalized(
        NORMALIZED_PATH, INDEX_PATH,
        backend_name=request.backend,
        strategy=request.strategy,
        window_minutes=request.window_minutes,
    )
    return IndexResponse(chunks_indexed=n)


@app.post("/ask", response_model=AskResponse)
def api_ask(request: AskRequest) -> AskResponse:
    """Ask a security question."""
    if not (INDEX_PATH / "index.faiss").exists():
        raise HTTPException(status_code=400, detail="No index found. Run /index first.")

    store = LocalVectorStore.load(INDEX_PATH)
    llm = get_llm_provider(request.llm_provider)
    assistant = RAGAssistant(store, llm=llm)
    result = assistant.query(
        request.query,
        host=request.host,
        severity=request.severity,
        hours=request.hours,
        k=request.k,
        hybrid_alpha=request.hybrid_alpha,
    )
    return AskResponse(query=result["query"], evidence=result["evidence"], answer=result["answer"])


@app.get("/status", response_model=StatusResponse)
def api_status() -> StatusResponse:
    """Get system status."""
    import json

    n_events = 0
    last_event_time = "never"
    if NORMALIZED_PATH.exists():
        lines = NORMALIZED_PATH.read_text().strip().splitlines()
        n_events = len(lines)
        if lines:
            last_event = json.loads(lines[-1])
            last_event_time = last_event.get("timestamp", "unknown")

    index_exists = (INDEX_PATH / "index.faiss").exists()
    n_indexed = 0
    if index_exists:
        meta_path = INDEX_PATH / "metadata.jsonl"
        if meta_path.exists():
            n_indexed = len(meta_path.read_text().strip().splitlines())

    n_audit = 0
    if AUDIT_PATH.exists():
        n_audit = len(AUDIT_PATH.read_text().strip().splitlines())

    return StatusResponse(
        events_ingested=n_events,
        events_indexed=n_indexed,
        index_exists=index_exists,
        last_event_time=last_event_time,
        audit_entries=n_audit,
    )
