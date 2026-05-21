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
def ingest(raw_path: Path, normalized_path: Path = Path("data/processed/normalized.jsonl")) -> None:
    n = ingest_jsonl(raw_path, normalized_path)
    typer.echo(f"Ingested {n} events to {normalized_path}")


@app.command()
def index(normalized_path: Path = Path("data/processed/normalized.jsonl"), index_path: Path = Path("data/index")) -> None:
    n = build_index_from_normalized(normalized_path, index_path)
    typer.echo(f"Indexed {n} events into {index_path}")


@app.command()
def ask(
    query: str,
    host: str | None = None,
    severity: str | None = None,
    hours: int | None = None,
    k: int = 5,
    format: str = "text",
    index_path: Path = Path("data/index"),
    audit_path: Path = Path("data/audit/interactions.jsonl"),
) -> None:
    store = LocalVectorStore.load(index_path)
    assistant = RAGAssistant(store)
    result = assistant.query(query, host=host, severity=severity, hours=hours, k=k)

    write_audit_log(audit_path, query=result["query"], evidence=result["evidence"], answer=result["answer"])

    if format == "json":
        typer.echo(json.dumps(result, indent=2))
    else:
        typer.echo("=== Retrieved Evidence ===")
        typer.echo(json.dumps(result["evidence"], indent=2))
        typer.echo("\n=== Generated Answer ===")
        typer.echo(result["answer"])


@app.command()
def status(
    normalized_path: Path = Path("data/processed/normalized.jsonl"),
    index_path: Path = Path("data/index"),
    audit_path: Path = Path("data/audit/interactions.jsonl"),
) -> None:
    """Show current system status: event counts, index size, audit entries."""
    n_events = 0
    last_ingest = "never"
    if normalized_path.exists():
        lines = normalized_path.read_text().strip().splitlines()
        n_events = len(lines)
        if lines:
            last_event = json.loads(lines[-1])
            last_ingest = last_event.get("timestamp", "unknown")

    index_exists = (index_path / "index.faiss").exists()
    n_indexed = 0
    if index_exists:
        meta_path = index_path / "metadata.jsonl"
        if meta_path.exists():
            n_indexed = len(meta_path.read_text().strip().splitlines())

    n_audit = 0
    if audit_path.exists():
        n_audit = len(audit_path.read_text().strip().splitlines())

    typer.echo(f"Events ingested:  {n_events}")
    typer.echo(f"Events indexed:   {n_indexed}")
    typer.echo(f"Index exists:     {index_exists}")
    typer.echo(f"Last event time:  {last_ingest}")
    typer.echo(f"Audit log entries: {n_audit}")


if __name__ == "__main__":
    app()
