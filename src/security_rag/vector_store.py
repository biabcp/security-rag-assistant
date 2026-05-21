from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

import faiss

from .embeddings import EmbeddingBackend, HashingBackend


class LocalVectorStore:
    """Vendor-neutral local vector store using FAISS + pluggable embeddings."""

    def __init__(self, backend: EmbeddingBackend | None = None):
        if backend is None:
            backend = HashingBackend()
        self.backend = backend
        self.index = faiss.IndexFlatIP(backend.dim)
        self.metadata: list[dict[str, Any]] = []
        self._corpus_texts: list[str] = []

    def add(self, docs: Iterable[dict[str, Any]]) -> int:
        docs = list(docs)
        texts = [d["chunk_text"] for d in docs]
        vectors = self.backend.embed(texts)
        self.index.add(vectors)
        self.metadata.extend(docs)
        self._corpus_texts.extend(texts)
        return len(docs)

    def search(
        self,
        query: str,
        k: int = 5,
        filters: dict[str, Any] | None = None,
        hybrid_alpha: float = 1.0,
    ) -> list[dict[str, Any]]:
        """Search with optional hybrid scoring (alpha=1.0 is pure semantic, 0.0 is pure BM25)."""
        q = self.backend.embed([query])
        n_search = min(k * 5, max(len(self.metadata), 1))
        scores, idx = self.index.search(q, n_search)

        bm25_scores: dict[int, float] = {}
        if hybrid_alpha < 1.0 and self._corpus_texts:
            bm25_scores = _bm25_scores(query, self._corpus_texts)

        out: list[dict[str, Any]] = []
        for sem_score, i in zip(scores[0], idx[0], strict=False):
            if i < 0 or i >= len(self.metadata):
                continue
            row = self.metadata[i]
            if filters and not _passes_filters(row, filters):
                continue

            final_score = hybrid_alpha * float(sem_score)
            if hybrid_alpha < 1.0:
                final_score += (1.0 - hybrid_alpha) * bm25_scores.get(int(i), 0.0)

            out.append({"score": final_score, **row})
            if len(out) >= k:
                break

        return out

    def save(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        faiss.write_index(self.index, str(path / "index.faiss"))
        with (path / "metadata.jsonl").open("w", encoding="utf-8") as f:
            for row in self.metadata:
                f.write(json.dumps(row) + "\n")

    @classmethod
    def load(cls, path: Path, backend: EmbeddingBackend | None = None) -> "LocalVectorStore":
        if backend is None:
            backend = HashingBackend()
        obj = cls(backend=backend)
        obj.index = faiss.read_index(str(path / "index.faiss"))
        with (path / "metadata.jsonl").open("r", encoding="utf-8") as f:
            obj.metadata = [json.loads(line) for line in f if line.strip()]
        obj._corpus_texts = [m.get("chunk_text", "") for m in obj.metadata]
        return obj


def _passes_filters(row: dict[str, Any], filters: dict[str, Any]) -> bool:
    for key, expected in filters.items():
        if expected is None:
            continue
        if key == "time_start" and row.get("timestamp") < expected:
            return False
        if key == "time_end" and row.get("timestamp") > expected:
            return False
        if key in {"host", "severity", "event_type"} and row.get(key) != expected:
            return False
    return True


def _bm25_scores(query: str, corpus: list[str], k1: float = 1.5, b: float = 0.75) -> dict[int, float]:
    """Compute BM25 scores for query against corpus."""
    query_terms = _tokenize(query)
    if not query_terms:
        return {}

    n = len(corpus)
    avg_dl = sum(len(_tokenize(doc)) for doc in corpus) / max(n, 1)

    df: Counter[str] = Counter()
    for doc in corpus:
        terms = set(_tokenize(doc))
        for t in terms:
            df[t] += 1

    scores: dict[int, float] = {}
    for idx, doc in enumerate(corpus):
        doc_terms = _tokenize(doc)
        dl = len(doc_terms)
        tf: Counter[str] = Counter(doc_terms)
        score = 0.0
        for term in query_terms:
            if term not in tf:
                continue
            idf = math.log((n - df[term] + 0.5) / (df[term] + 0.5) + 1.0)
            term_tf = tf[term]
            numerator = term_tf * (k1 + 1)
            denominator = term_tf + k1 * (1 - b + b * dl / avg_dl)
            score += idf * numerator / denominator
        if score > 0:
            scores[idx] = score

    max_score = max(scores.values()) if scores else 1.0
    return {i: s / max_score for i, s in scores.items()}


def _tokenize(text: str) -> list[str]:
    return re.findall(r"\w+", text.lower())
