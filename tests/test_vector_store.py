from __future__ import annotations

from pathlib import Path

from security_rag.vector_store import LocalVectorStore


def _sample_docs() -> list[dict]:
    return [
        {"event_id": "e1", "host": "h1", "severity": "high", "event_type": "login",
         "timestamp": "2026-04-24T10:00:00+00:00", "chunk_text": "login failed invalid password"},
        {"event_id": "e2", "host": "h2", "severity": "low", "event_type": "network",
         "timestamp": "2026-04-24T11:00:00+00:00", "chunk_text": "outbound network connection established"},
        {"event_id": "e3", "host": "h1", "severity": "high", "event_type": "process",
         "timestamp": "2026-04-24T12:00:00+00:00", "chunk_text": "powershell encoded command execution detected"},
    ]


def test_index_creation_and_count() -> None:
    store = LocalVectorStore()
    n = store.add(_sample_docs())
    assert n == 3
    assert len(store.metadata) == 3


def test_retrieval_returns_results() -> None:
    store = LocalVectorStore()
    store.add(_sample_docs())
    results = store.search("login failed", k=2)
    assert len(results) <= 2
    assert all("score" in r for r in results)


def test_retrieval_ranking() -> None:
    store = LocalVectorStore()
    store.add(_sample_docs())
    results = store.search("login failed password", k=3)
    assert results[0]["event_id"] == "e1"


def test_save_and_load(tmp_path: Path) -> None:
    store = LocalVectorStore()
    store.add(_sample_docs())
    store.save(tmp_path / "idx")

    loaded = LocalVectorStore.load(tmp_path / "idx")
    assert len(loaded.metadata) == 3
    results = loaded.search("powershell", k=1)
    assert results[0]["event_id"] == "e3"


def test_empty_index_search() -> None:
    store = LocalVectorStore()
    results = store.search("anything", k=5)
    assert results == []


def test_host_filter() -> None:
    store = LocalVectorStore()
    store.add(_sample_docs())
    results = store.search("login", k=5, filters={"host": "h2"})
    assert all(r["host"] == "h2" for r in results)
