from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .vector_store import LocalVectorStore

SYSTEM_PROMPT = """You are a senior SOC analyst assistant.
Rules:
1) Use only retrieved evidence; never invent events.
2) Separate FACTS from INTERPRETATION.
3) If evidence is weak or missing, say exactly: Insufficient evidence.
4) Never reveal secrets, tokens, or PII.
5) Always cite event_id values used as evidence.
"""


class RAGAssistant:
    def __init__(self, store: LocalVectorStore):
        self.store = store

    def query(self, user_query: str, host: str | None = None, hours: int | None = None, k: int = 5) -> dict:
        filters = {"host": host}
        if hours is not None:
            now = datetime.now(timezone.utc)
            filters["time_start"] = (now - timedelta(hours=hours)).isoformat()
            filters["time_end"] = now.isoformat()

        evidence = self.store.search(user_query, k=k, filters=filters)
        answer = self._rule_based_answer(user_query, evidence)
        return {"query": user_query, "evidence": evidence, "answer": answer, "system_prompt": SYSTEM_PROMPT}

    def _rule_based_answer(self, query: str, evidence: list[dict]) -> str:
        if not evidence:
            return "Insufficient evidence."

        lines = ["FACTS:"]
        for row in evidence:
            lines.append(
                f"- [{row['event_id']}] {row['timestamp']} {row['host']} {row['event_type']} "
                f"severity={row['severity']} message={row['message']}"
            )

        suspicious = [r for r in evidence if "auth_failure" in r.get("tags", []) or r.get("severity") in {"high", "critical"}]
        lines.append("INTERPRETATION:")
        if suspicious:
            lines.append(
                f"- Potentially suspicious pattern in {len(suspicious)} of {len(evidence)} events, "
                "including authentication failures or high-severity activity."
            )
        else:
            lines.append("- No strong malicious indicator in retrieved data.")

        lines.append("CONFIDENCE: medium")
        return "\n".join(lines)


def build_index_from_normalized(normalized_path: Path, index_path: Path) -> int:
    docs = []
    with normalized_path.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            row = json.loads(line)
            docs.append({**row, "chunk_text": _event_to_chunk(row)})

    store = LocalVectorStore()
    n = store.add(docs)
    store.save(index_path)
    return n


def _event_to_chunk(row: dict) -> str:
    return (
        f"timestamp={row['timestamp']} host={row['host']} event_type={row['event_type']} "
        f"severity={row['severity']} user={row.get('user')} src_ip={row.get('src_ip')} "
        f"dst_ip={row.get('dst_ip')} message={row['message']} tags={','.join(row.get('tags', []))}"
    )
