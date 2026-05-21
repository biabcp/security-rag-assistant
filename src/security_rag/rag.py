from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .chunking import event_chunks, session_chunks
from .embeddings import get_backend
from .llm import LLMProvider, RuleBasedProvider, detect_prompt_injection
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
    def __init__(self, store: LocalVectorStore, llm: LLMProvider | None = None):
        self.store = store
        self.llm = llm or RuleBasedProvider()

    def query(
        self,
        user_query: str,
        host: str | None = None,
        severity: str | None = None,
        hours: int | None = None,
        k: int = 5,
        hybrid_alpha: float = 1.0,
    ) -> dict[str, Any]:
        if detect_prompt_injection(user_query):
            return {
                "query": user_query,
                "evidence": [],
                "answer": "Query rejected: potential prompt injection detected.",
                "system_prompt": SYSTEM_PROMPT,
            }

        filters: dict[str, Any] = {}
        if host:
            filters["host"] = host
        if severity:
            filters["severity"] = severity
        if hours is not None:
            now = datetime.now(timezone.utc)
            filters["time_start"] = (now - timedelta(hours=hours)).isoformat()
            filters["time_end"] = now.isoformat()

        evidence = self.store.search(user_query, k=k, filters=filters, hybrid_alpha=hybrid_alpha)
        answer = self._generate_answer(user_query, evidence)
        return {"query": user_query, "evidence": evidence, "answer": answer, "system_prompt": SYSTEM_PROMPT}

    def _generate_answer(self, query: str, evidence: list[dict[str, Any]]) -> str:
        """Try LLM generation, fall back to rule-based."""
        if evidence:
            evidence_text = "\n".join(
                f"[{e['event_id']}] {e['timestamp']} {e['host']} {e['event_type']} "
                f"severity={e['severity']} message={e['message']}"
                for e in evidence
            )
            user_message = f"Query: {query}\n\nRetrieved Evidence:\n{evidence_text}"

            llm_answer = self.llm.generate(SYSTEM_PROMPT, user_message)
            if llm_answer:
                return llm_answer

        return self._rule_based_answer(query, evidence)

    def _rule_based_answer(self, query: str, evidence: list[dict[str, Any]]) -> str:
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


def build_index_from_normalized(
    normalized_path: Path,
    index_path: Path,
    backend_name: str = "hashing",
    strategy: str = "event",
    window_minutes: int = 5,
) -> int:
    raw_docs = []
    with normalized_path.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            raw_docs.append(json.loads(line))

    if strategy == "session":
        docs = session_chunks(raw_docs, window_minutes=window_minutes)
    else:
        docs = event_chunks(raw_docs)

    backend = get_backend(backend_name)
    store = LocalVectorStore(backend=backend)
    n = store.add(docs)
    store.save(index_path)
    return n
