from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class NormalizedEvent:
    event_id: str
    timestamp: datetime
    host: str
    source: str
    event_type: str
    severity: str
    user: str | None
    process: str | None
    src_ip: str | None
    dst_ip: str | None
    message: str
    tags: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_chunk_text(self) -> str:
        ts = self.timestamp.astimezone(timezone.utc).isoformat()
        tags = ",".join(sorted(self.tags)) if self.tags else "none"
        return (
            f"timestamp={ts} host={self.host} source={self.source} "
            f"type={self.event_type} severity={self.severity} user={self.user} "
            f"src_ip={self.src_ip} dst_ip={self.dst_ip} process={self.process} tags={tags} "
            f"message={self.message}"
        )
