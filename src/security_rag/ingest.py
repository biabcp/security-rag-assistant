from __future__ import annotations

import json
from pathlib import Path

from .preprocess import load_jsonl, normalize_event


def ingest_jsonl(raw_path: Path, normalized_path: Path, source: str = "jsonl") -> int:
    raw_events = load_jsonl(raw_path)
    normalized_path.parent.mkdir(parents=True, exist_ok=True)

    with normalized_path.open("w", encoding="utf-8") as out:
        for event in raw_events:
            normalized = normalize_event(event, source=source)
            out.write(
                json.dumps(
                    {
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
                )
                + "\n"
            )

    return len(raw_events)
