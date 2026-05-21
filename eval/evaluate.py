"""Evaluation harness for retrieval and answer quality."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from security_rag.vector_store import LocalVectorStore


def precision_at_k(retrieved: list[str], relevant: set[str], k: int) -> float:
    """Precision@k: fraction of top-k retrieved items that are relevant."""
    top_k = retrieved[:k]
    if not top_k:
        return 0.0
    hits = sum(1 for eid in top_k if eid in relevant)
    return hits / len(top_k)


def recall_at_k(retrieved: list[str], relevant: set[str], k: int) -> float:
    """Recall@k: fraction of relevant items found in top-k."""
    if not relevant:
        return 1.0
    top_k = retrieved[:k]
    hits = sum(1 for eid in top_k if eid in relevant)
    return hits / len(relevant)


def mean_reciprocal_rank(retrieved: list[str], relevant: set[str]) -> float:
    """MRR: reciprocal of the rank of the first relevant result."""
    for i, eid in enumerate(retrieved, 1):
        if eid in relevant:
            return 1.0 / i
    return 0.0


def check_hallucination(answer: str, retrieved_event_ids: set[str]) -> list[str]:
    """Find event IDs cited in the answer that were not in retrieved evidence."""
    import re
    cited = set(re.findall(r"\[([a-f0-9]{16})\]", answer))
    hallucinated = cited - retrieved_event_ids
    return sorted(hallucinated)


def run_evaluation(
    index_path: Path,
    golden_path: Path,
    k_values: list[int] | None = None,
) -> dict[str, Any]:
    """Run evaluation against golden queries and return metrics."""
    if k_values is None:
        k_values = [3, 5, 10]

    store = LocalVectorStore.load(index_path)

    golden_queries: list[dict[str, Any]] = []
    with golden_path.open("r") as f:
        for line in f:
            if line.strip():
                golden_queries.append(json.loads(line))

    results: dict[str, Any] = {
        "num_queries": len(golden_queries),
        "metrics": {},
        "per_query": [],
    }

    all_precision: dict[int, list[float]] = {k: [] for k in k_values}
    all_recall: dict[int, list[float]] = {k: [] for k in k_values}
    all_mrr: list[float] = []
    total_hallucinations = 0

    for query_data in golden_queries:
        query = query_data["query"]
        relevant = set(query_data["relevant_event_ids"])

        evidence = store.search(query, k=max(k_values))
        retrieved_ids = [e["event_id"] for e in evidence]

        from security_rag.rag import RAGAssistant
        assistant = RAGAssistant(store)
        result = assistant.query(query, k=max(k_values))
        hallucinated = check_hallucination(result["answer"], set(retrieved_ids))
        total_hallucinations += len(hallucinated)

        query_metrics: dict[str, Any] = {"query": query, "hallucinated_ids": hallucinated}

        for k in k_values:
            p = precision_at_k(retrieved_ids, relevant, k)
            r = recall_at_k(retrieved_ids, relevant, k)
            all_precision[k].append(p)
            all_recall[k].append(r)
            query_metrics[f"precision@{k}"] = p
            query_metrics[f"recall@{k}"] = r

        mrr = mean_reciprocal_rank(retrieved_ids, relevant)
        all_mrr.append(mrr)
        query_metrics["mrr"] = mrr

        results["per_query"].append(query_metrics)

    for k in k_values:
        results["metrics"][f"mean_precision@{k}"] = (
            sum(all_precision[k]) / len(all_precision[k]) if all_precision[k] else 0.0
        )
        results["metrics"][f"mean_recall@{k}"] = (
            sum(all_recall[k]) / len(all_recall[k]) if all_recall[k] else 0.0
        )

    results["metrics"]["mean_mrr"] = sum(all_mrr) / len(all_mrr) if all_mrr else 0.0
    results["metrics"]["total_hallucinations"] = total_hallucinations

    return results
