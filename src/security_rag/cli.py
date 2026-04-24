from __future__ import annotations

import json
from pathlib import Path

import typer

from .audit import write_audit_log
from .ingest import ingest_jsonl
from .rag import RAGAssistant, build_index_from_normalized
from .vector_store import LocalVectorStore

app = typer.Typer(help="Security RAG Assistant")


@app.command()
def ingest(raw_path: Path, normalized_path: Path = Path("data/processed/normalized.jsonl")):
    n = ingest_jsonl(raw_path, normalized_path)
    typer.echo(f"Ingested {n} events to {normalized_path}")


@app.command()
def index(normalized_path: Path = Path("data/processed/normalized.jsonl"), index_path: Path = Path("data/index")):
    n = build_index_from_normalized(normalized_path, index_path)
    typer.echo(f"Indexed {n} events into {index_path}")


@app.command()
def ask(
    query: str,
    host: str | None = None,
    hours: int | None = None,
    k: int = 5,
    index_path: Path = Path("data/index"),
    audit_path: Path = Path("data/audit/interactions.jsonl"),
):
    store = LocalVectorStore.load(index_path)
    assistant = RAGAssistant(store)
    result = assistant.query(query, host=host, hours=hours, k=k)

    write_audit_log(audit_path, query=result["query"], evidence=result["evidence"], answer=result["answer"])

    typer.echo("=== Retrieved Evidence ===")
    typer.echo(json.dumps(result["evidence"], indent=2))
    typer.echo("\n=== Generated Answer ===")
    typer.echo(result["answer"])


if __name__ == "__main__":
    app()
