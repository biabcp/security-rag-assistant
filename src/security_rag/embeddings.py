"""Pluggable embedding backends for the vector store."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, cast

import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer


class EmbeddingBackend(ABC):
    """Abstract base class for embedding backends."""

    @property
    @abstractmethod
    def dim(self) -> int:
        ...

    @abstractmethod
    def embed(self, texts: list[str]) -> np.ndarray:
        """Return float32 array of shape (len(texts), dim)."""
        ...


class HashingBackend(EmbeddingBackend):
    """Deterministic hashing vectorizer. No external API needed."""

    def __init__(self, n_features: int = 1024):
        self._dim = n_features
        self._vectorizer = HashingVectorizer(
            n_features=n_features, alternate_sign=False, norm="l2"
        )

    @property
    def dim(self) -> int:
        return self._dim

    def embed(self, texts: list[str]) -> np.ndarray:
        result = self._vectorizer.transform(texts).toarray().astype(np.float32)
        return cast(np.ndarray, result)


class SentenceTransformerBackend(EmbeddingBackend):
    """sentence-transformers backend for higher quality semantic embeddings."""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as e:
            raise ImportError(
                "sentence-transformers is required for this backend. "
                "Install with: pip install sentence-transformers"
            ) from e
        self._model: Any = SentenceTransformer(model_name)
        self._dim = self._model.get_sentence_embedding_dimension()

    @property
    def dim(self) -> int:
        return int(self._dim)

    def embed(self, texts: list[str]) -> np.ndarray:
        embeddings = self._model.encode(texts, normalize_embeddings=True)
        return np.array(embeddings, dtype=np.float32)


def get_backend(name: str = "hashing", **kwargs: Any) -> EmbeddingBackend:
    """Factory function to get an embedding backend by name."""
    if name == "hashing":
        return HashingBackend(**kwargs)
    elif name == "sentence-transformer":
        return SentenceTransformerBackend(**kwargs)
    else:
        raise ValueError(f"Unknown embedding backend: {name}. Use 'hashing' or 'sentence-transformer'.")
