from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def write_audit_log(audit_path: Path, query: str, evidence: list[dict], answer: str) -> None:
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "query": query,
        "evidence_event_ids": [e.get("event_id") for e in evidence],
        "retrieved_documents": evidence,
        "response": answer,
    }
    with audit_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload) + "\n")
