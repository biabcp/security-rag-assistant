from __future__ import annotations

import json
from pathlib import Path

from security_rag.ingest import ingest_jsonl
from security_rag.rag import RAGAssistant, build_index_from_normalized
from security_rag.vector_store import LocalVectorStore


def test_full_pipeline(tmp_path: Path) -> None:
    """End-to-end: ingest -> index -> ask pipeline."""
    raw_path = tmp_path / "raw.jsonl"
    normalized_path = tmp_path / "normalized.jsonl"
    index_path = tmp_path / "index"

    events = [
        {"timestamp": "2026-04-24T10:00:00Z", "host": "srv-auth-01", "event_type": "login",
         "severity": "high", "user": "alice", "src_ip": "203.0.113.4",
         "message": "Login failed: invalid password", "token": "secret"},
        {"timestamp": "2026-04-24T10:05:00Z", "host": "srv-auth-01", "event_type": "login",
         "severity": "high", "user": "alice", "src_ip": "203.0.113.4",
         "message": "Multiple failed authentication attempts"},
        {"timestamp": "2026-04-24T11:15:00Z", "host": "srv-fin-02", "event_type": "process_create",
         "severity": "high", "user": "svc-fin", "process": "powershell.exe",
         "src_ip": "10.0.0.12", "message": "Encoded command execution detected"},
    ]
    with raw_path.open("w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")

    n_ingested = ingest_jsonl(raw_path, normalized_path)
    assert n_ingested == 3

    n_indexed = build_index_from_normalized(normalized_path, index_path)
    assert n_indexed == 3

    store = LocalVectorStore.load(index_path)
    assistant = RAGAssistant(store)

    result = assistant.query("Show suspicious login activity")
    assert result["evidence"]
    assert "FACTS:" in result["answer"]

    login_events = [e for e in result["evidence"] if e["event_type"] == "login"]
    assert len(login_events) >= 1

    result2 = assistant.query("encoded command execution")
    assert result2["evidence"]
    top_event = result2["evidence"][0]
    assert top_event["event_type"] == "process_create"
    assert "Encoded command" in top_event["message"]


def test_pipeline_with_redaction(tmp_path: Path) -> None:
    """Verify sensitive data is redacted through the full pipeline."""
    raw_path = tmp_path / "raw.jsonl"
    normalized_path = tmp_path / "normalized.jsonl"
    index_path = tmp_path / "index"

    events = [
        {"timestamp": "2026-04-24T10:00:00Z", "host": "h1", "event_type": "login",
         "severity": "low", "message": "ok", "password": "hunter2", "api_key": "sk-abc123"}
    ]
    with raw_path.open("w") as f:
        f.write(json.dumps(events[0]) + "\n")

    ingest_jsonl(raw_path, normalized_path)
    build_index_from_normalized(normalized_path, index_path)

    store = LocalVectorStore.load(index_path)
    result = store.search("login", k=1)
    assert result[0]["raw"]["password"] == "[REDACTED]"
    assert result[0]["raw"]["api_key"] == "[REDACTED]"
