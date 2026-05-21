"""Chunking strategies for security events."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from dateutil import parser as dtparser


def event_chunks(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Default: one chunk per event."""
    result = []
    for row in events:
        result.append({**row, "chunk_text": _event_to_chunk(row)})
    return result


def session_chunks(
    events: list[dict[str, Any]],
    window_minutes: int = 5,
) -> list[dict[str, Any]]:
    """Session-based chunking: group events by (user, host, time window)."""
    groups: defaultdict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)

    for event in events:
        user = event.get("user") or "unknown"
        host = event.get("host") or "unknown"
        groups[(user, host)].append(event)

    result = []
    for (user, host), group_events in groups.items():
        sorted_events = sorted(group_events, key=lambda e: e.get("timestamp", ""))
        current_session: list[dict[str, Any]] = []
        session_start: datetime | None = None

        for event in sorted_events:
            ts_str = event.get("timestamp", "")
            try:
                ts = dtparser.parse(ts_str)
            except (ValueError, TypeError):
                ts = None

            if not current_session or (
                ts and session_start and ts - session_start <= timedelta(minutes=window_minutes)
            ):
                current_session.append(event)
                if ts and session_start is None:
                    session_start = ts
            else:
                result.append(_merge_session(current_session))
                current_session = [event]
                session_start = ts

        if current_session:
            result.append(_merge_session(current_session))

    return result


def _merge_session(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge a session of events into a single chunk."""
    base = events[0].copy()
    messages = [e.get("message", "") for e in events]
    all_tags: list[str] = []
    for e in events:
        all_tags.extend(e.get("tags", []))

    event_ids = [e["event_id"] for e in events]
    chunk_parts = []
    for e in events:
        chunk_parts.append(_event_to_chunk(e))

    base["chunk_text"] = " | ".join(chunk_parts)
    base["session_event_ids"] = event_ids
    base["message"] = " ; ".join(messages)
    base["tags"] = list(set(all_tags))
    return base


def _event_to_chunk(row: dict[str, Any]) -> str:
    return (
        f"timestamp={row.get('timestamp')} host={row.get('host')} event_type={row.get('event_type')} "
        f"severity={row.get('severity')} user={row.get('user')} src_ip={row.get('src_ip')} "
        f"dst_ip={row.get('dst_ip')} message={row.get('message')} tags={','.join(row.get('tags', []))}"
    )
