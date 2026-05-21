from __future__ import annotations

import json
from pathlib import Path

from security_rag.ingest import ingest_jsonl


def _write_jsonl(path: Path, events: list[dict]) -> None:
    with path.open("w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


def test_valid_jsonl_parsing(tmp_path: Path) -> None:
    raw = tmp_path / "raw.jsonl"
    out = tmp_path / "normalized.jsonl"
    events = [
        {"timestamp": "2026-04-24T10:00:00Z", "host": "h1", "event_type": "login", "severity": "high", "message": "ok"},
        {"timestamp": "2026-04-24T11:00:00Z", "host": "h2", "event_type": "network", "severity": "low", "message": "conn"},
    ]
    _write_jsonl(raw, events)
    n = ingest_jsonl(raw, out)
    assert n == 2
    lines = [json.loads(l) for l in out.read_text().strip().splitlines()]
    assert len(lines) == 2
    assert lines[0]["host"] == "h1"
    assert lines[1]["host"] == "h2"


def test_timestamp_normalization(tmp_path: Path) -> None:
    raw = tmp_path / "raw.jsonl"
    out = tmp_path / "normalized.jsonl"
    events = [
        {"timestamp": "2026-04-24T10:00:00Z", "host": "h1", "event_type": "x", "severity": "low", "message": "m"},
        {"timestamp": "2026-04-24T10:00:00+05:00", "host": "h2", "event_type": "x", "severity": "low", "message": "m"},
        {"timestamp": "2026-04-24T10:00:00", "host": "h3", "event_type": "x", "severity": "low", "message": "m"},
    ]
    _write_jsonl(raw, events)
    ingest_jsonl(raw, out)
    lines = [json.loads(l) for l in out.read_text().strip().splitlines()]
    assert "+00:00" in lines[0]["timestamp"] or "Z" in lines[0]["timestamp"]
    assert "+05:00" in lines[1]["timestamp"] or "05:00" in lines[1]["timestamp"]


def test_overwrite_on_reingest(tmp_path: Path) -> None:
    raw = tmp_path / "raw.jsonl"
    out = tmp_path / "normalized.jsonl"
    events = [{"timestamp": "2026-04-24T10:00:00Z", "host": "h1", "event_type": "x", "severity": "low", "message": "m"}]
    _write_jsonl(raw, events)
    ingest_jsonl(raw, out)
    ingest_jsonl(raw, out)
    lines = out.read_text().strip().splitlines()
    assert len(lines) == 1


def test_empty_file(tmp_path: Path) -> None:
    raw = tmp_path / "raw.jsonl"
    out = tmp_path / "normalized.jsonl"
    raw.write_text("")
    n = ingest_jsonl(raw, out)
    assert n == 0
    assert out.exists()


def test_redaction_during_ingest(tmp_path: Path) -> None:
    raw = tmp_path / "raw.jsonl"
    out = tmp_path / "normalized.jsonl"
    events = [
        {"timestamp": "2026-04-24T10:00:00Z", "host": "h1", "event_type": "login", "severity": "high",
         "message": "fail", "token": "secret123456789012345678"}
    ]
    _write_jsonl(raw, events)
    ingest_jsonl(raw, out)
    line = json.loads(out.read_text().strip())
    assert line["raw"]["token"] == "[REDACTED]"
