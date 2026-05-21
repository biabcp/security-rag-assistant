from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .preprocess import load_jsonl, normalize_event


def _load_existing_event_ids(normalized_path: Path) -> set[str]:
    """Load event_ids of already-ingested events for deduplication."""
    ids: set[str] = set()
    if not normalized_path.exists():
        return ids
    with normalized_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            ids.add(row["event_id"])
    return ids


def _serialize_event(event: dict[str, Any], source: str) -> tuple[str, str]:
    """Normalize and serialize an event. Returns (event_id, json_line)."""
    normalized = normalize_event(event, source=source)
    record = {
        "event_id": normalized.event_id,
        "timestamp": normalized.timestamp.isoformat(),
        "host": normalized.host,
        "source": normalized.source,
        "event_type": normalized.event_type,
        "severity": normalized.severity,
        "user": normalized.user,
        "process": normalized.process,
        "src_ip": normalized.src_ip,
        "dst_ip": normalized.dst_ip,
        "message": normalized.message,
        "tags": normalized.tags,
        "raw": normalized.raw,
    }
    return normalized.event_id, json.dumps(record) + "\n"


def ingest_jsonl(
    raw_path: Path,
    normalized_path: Path,
    source: str = "jsonl",
    append: bool = False,
) -> int:
    raw_events = load_jsonl(raw_path)
    return _write_events(raw_events, normalized_path, source=source, append=append)


def ingest_csv(
    raw_path: Path,
    normalized_path: Path,
    source: str = "csv",
    append: bool = False,
) -> int:
    """Ingest a CSV log file. Columns become event fields."""
    events: list[dict[str, Any]] = []
    with raw_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            events.append(dict(row))
    return _write_events(events, normalized_path, source=source, append=append)


def ingest_directory(
    dir_path: Path,
    normalized_path: Path,
    append: bool = True,
) -> int:
    """Ingest all .jsonl and .csv files from a directory."""
    total = 0
    files = sorted(dir_path.iterdir())
    for f in files:
        if f.suffix == ".jsonl":
            total += ingest_jsonl(f, normalized_path, append=append)
            append = True
        elif f.suffix == ".csv":
            total += ingest_csv(f, normalized_path, append=append)
            append = True
    return total


def _write_events(
    events: list[dict[str, Any]],
    normalized_path: Path,
    source: str,
    append: bool,
) -> int:
    normalized_path.parent.mkdir(parents=True, exist_ok=True)

    if append:
        existing_ids = _load_existing_event_ids(normalized_path)
        mode = "a"
    else:
        existing_ids = set()
        mode = "w"

    written = 0
    with normalized_path.open(mode, encoding="utf-8") as out:
        for event in events:
            event_id, line = _serialize_event(event, source=source)
            if event_id not in existing_ids:
                out.write(line)
                existing_ids.add(event_id)
                written += 1

    return written
