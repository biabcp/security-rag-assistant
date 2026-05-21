from __future__ import annotations

import json
from pathlib import Path

from security_rag.audit import write_audit_log


def test_audit_log_creation(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit" / "interactions.jsonl"
    write_audit_log(audit_path, query="test query", evidence=[{"event_id": "e1"}], answer="test answer")
    assert audit_path.exists()
    entry = json.loads(audit_path.read_text().strip())
    assert entry["query"] == "test query"
    assert entry["response"] == "test answer"
    assert entry["evidence_event_ids"] == ["e1"]
    assert "timestamp" in entry


def test_audit_log_appends(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit" / "interactions.jsonl"
    write_audit_log(audit_path, query="q1", evidence=[], answer="a1")
    write_audit_log(audit_path, query="q2", evidence=[], answer="a2")
    lines = audit_path.read_text().strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["query"] == "q1"
    assert json.loads(lines[1])["query"] == "q2"


def test_audit_creates_parent_dirs(tmp_path: Path) -> None:
    audit_path = tmp_path / "deep" / "nested" / "dir" / "audit.jsonl"
    write_audit_log(audit_path, query="q", evidence=[], answer="a")
    assert audit_path.exists()


def test_audit_json_structure(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    evidence = [{"event_id": "e1", "host": "h1"}, {"event_id": "e2", "host": "h2"}]
    write_audit_log(audit_path, query="q", evidence=evidence, answer="a")
    entry = json.loads(audit_path.read_text().strip())
    assert entry["evidence_event_ids"] == ["e1", "e2"]
    assert entry["retrieved_documents"] == evidence
