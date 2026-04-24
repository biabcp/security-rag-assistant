from __future__ import annotations

from dataclasses import dataclass

from security_rag.rag import RAGAssistant
from security_rag.vector_store import LocalVectorStore


@dataclass
class EvalCase:
    query: str
    expected_event_ids: set[str]


def precision_at_k(retrieved: list[dict], expected: set[str], k: int) -> float:
    top = retrieved[:k]
    if not top:
        return 0.0
    relevant = sum(1 for r in top if r["event_id"] in expected)
    return relevant / len(top)


def likely_hallucination(answer: str, retrieved_event_ids: set[str]) -> bool:
    for token in answer.replace("[", " ").replace("]", " ").split():
        if len(token) == 16 and token.isalnum() and token not in retrieved_event_ids:
            return True
    return False


def run_eval(index_path: str = "data/index"):
    store = LocalVectorStore.load(__import__("pathlib").Path(index_path))
    assistant = RAGAssistant(store)

    cases = [
        EvalCase("Show suspicious login activity", set()),
    ]

    for case in cases:
        result = assistant.query(case.query, k=5)
        got_ids = {e["event_id"] for e in result["evidence"]}
        p5 = precision_at_k(result["evidence"], case.expected_event_ids or got_ids, k=5)
        halluc = likely_hallucination(result["answer"], got_ids)
        print({"query": case.query, "precision@5": p5, "hallucination_flag": halluc})


if __name__ == "__main__":
    run_eval()
