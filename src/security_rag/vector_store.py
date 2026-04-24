from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

import faiss
import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer


class LocalVectorStore:
    """Vendor-neutral local vector store using FAISS + deterministic hashing vectors."""

    def __init__(self, dim: int = 1024):
        self.dim = dim
        self.vectorizer = HashingVectorizer(n_features=dim, alternate_sign=False, norm="l2")
        self.index = faiss.IndexFlatIP(dim)
        self.metadata: list[dict] = []

    def add(self, docs: Iterable[dict]) -> int:
        docs = list(docs)
        texts = [d["chunk_text"] for d in docs]
        vectors = self.vectorizer.transform(texts).toarray().astype(np.float32)
        self.index.add(vectors)
        self.metadata.extend(docs)
        return len(docs)

    def search(self, query: str, k: int = 5, filters: dict | None = None) -> list[dict]:
        q = self.vectorizer.transform([query]).toarray().astype(np.float32)
        scores, idx = self.index.search(q, min(k * 5, max(len(self.metadata), 1)))
        out: list[dict] = []

        for score, i in zip(scores[0], idx[0], strict=False):
            if i < 0 or i >= len(self.metadata):
                continue
            row = self.metadata[i]
            if filters and not _passes_filters(row, filters):
                continue
            out.append({"score": float(score), **row})
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
    def load(cls, path: Path, dim: int = 1024) -> "LocalVectorStore":
        obj = cls(dim=dim)
        obj.index = faiss.read_index(str(path / "index.faiss"))
        with (path / "metadata.jsonl").open("r", encoding="utf-8") as f:
            obj.metadata = [json.loads(line) for line in f if line.strip()]
        return obj


def _passes_filters(row: dict, filters: dict) -> bool:
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
