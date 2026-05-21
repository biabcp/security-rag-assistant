from __future__ import annotations

import json
from pathlib import Path

from security_rag.rag import RAGAssistant, build_index_from_normalized
from security_rag.vector_store import LocalVectorStore


def _build_store() -> LocalVectorStore:
    store = LocalVectorStore()
    store.add([
        {"event_id": "e1", "host": "h1", "severity": "high", "event_type": "login",
         "timestamp": "2026-04-24T10:00:00+00:00", "message": "Login failed",
         "tags": ["auth_failure"], "chunk_text": "login failed invalid password"},
        {"event_id": "e2", "host": "h2", "severity": "low", "event_type": "network",
         "timestamp": "2026-04-24T11:00:00+00:00", "message": "Connection ok",
         "tags": [], "chunk_text": "outbound network connection established"},
    ])
    return store


def test_rule_based_answer_with_evidence() -> None:
    assistant = RAGAssistant(_build_store())
    result = assistant.query("login failed")
    assert "FACTS:" in result["answer"]
    assert "CONFIDENCE:" in result["answer"]
    assert result["evidence"]


def test_insufficient_evidence_fallback() -> None:
    store = LocalVectorStore()
    assistant = RAGAssistant(store)
    result = assistant.query("anything")
    assert result["answer"] == "Insufficient evidence."


def test_suspicious_pattern_detected() -> None:
    assistant = RAGAssistant(_build_store())
    result = assistant.query("login failed")
    assert "suspicious" in result["answer"].lower() or "auth_failure" in str(result["evidence"])


def test_build_index_from_normalized(tmp_path: Path) -> None:
    normalized = tmp_path / "normalized.jsonl"
    events = [
        {"event_id": "e1", "timestamp": "2026-04-24T10:00:00+00:00", "host": "h1",
         "source": "jsonl", "event_type": "login", "severity": "high",
         "user": "alice", "process": None, "src_ip": "1.2.3.4", "dst_ip": None,
         "message": "Failed login", "tags": ["auth_failure"], "raw": {}},
    ]
    with normalized.open("w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")

    index_path = tmp_path / "index"
    n = build_index_from_normalized(normalized, index_path)
    assert n == 1
    assert (index_path / "index.faiss").exists()
    assert (index_path / "metadata.jsonl").exists()


def test_query_returns_system_prompt() -> None:
    assistant = RAGAssistant(_build_store())
    result = assistant.query("test")
    assert "system_prompt" in result
    assert "SOC analyst" in result["system_prompt"]
