from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import UTC
from pathlib import Path
from typing import Any

from dateutil import parser as dtparser

from .schemas import NormalizedEvent

SENSITIVE_KEYS = {"password", "token", "secret", "api_key", "authorization", "ssn"}


def redact_dict(obj: dict[str, Any]) -> dict[str, Any]:
    redacted = {}
    for k, v in obj.items():
        if k.lower() in SENSITIVE_KEYS:
            redacted[k] = "[REDACTED]"
        elif isinstance(v, dict):
            redacted[k] = redact_dict(v)
        elif isinstance(v, str) and looks_like_secret(v):
            redacted[k] = "[REDACTED_VALUE]"
        else:
            redacted[k] = v
    return redacted


def looks_like_secret(value: str) -> bool:
    # Simple heuristic for JWT-like blobs and long opaque tokens
    return bool(re.match(r"^[A-Za-z0-9_-]{24,}$", value))


def classify_ip(ip: str | None) -> str:
    if not ip:
        return "unknown"
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private:
            return "private"
        if addr.is_loopback:
            return "loopback"
        return "public"
    except ValueError:
        return "invalid"


def normalize_event(raw_event: dict[str, Any], source: str = "unknown") -> NormalizedEvent:
    event = redact_dict(raw_event)
    timestamp_raw = event.get("timestamp") or event.get("time")
    timestamp = dtparser.parse(timestamp_raw).astimezone(UTC) if timestamp_raw else dtparser.parse("1970-01-01T00:00:00Z")

    host = str(event.get("host") or event.get("hostname") or "unknown-host")
    event_type = str(event.get("event_type") or event.get("type") or "generic")
    severity = str(event.get("severity") or "unknown").lower()
    src_ip = event.get("src_ip") or event.get("source_ip")
    dst_ip = event.get("dst_ip") or event.get("destination_ip")
    user = event.get("user")
    process = event.get("process") or event.get("process_name")
    message = str(event.get("message") or json.dumps(event, sort_keys=True))

    tags = [
        f"src_{classify_ip(src_ip)}",
        f"dst_{classify_ip(dst_ip)}",
    ]
    if "fail" in message.lower() or "denied" in message.lower():
        tags.append("auth_failure")

    stable_id = hashlib.sha256(
        f"{timestamp.isoformat()}|{host}|{event_type}|{message}".encode("utf-8")
    ).hexdigest()[:16]

    return NormalizedEvent(
        event_id=stable_id,
        timestamp=timestamp,
        host=host,
        source=source,
        event_type=event_type,
        severity=severity,
        user=str(user) if user is not None else None,
        process=str(process) if process is not None else None,
        src_ip=str(src_ip) if src_ip is not None else None,
        dst_ip=str(dst_ip) if dst_ip is not None else None,
        message=message,
        tags=tags,
        raw=event,
    )


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows
