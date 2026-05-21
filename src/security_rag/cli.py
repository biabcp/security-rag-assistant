from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import typer

from .audit import write_audit_log
from .ingest import ingest_csv, ingest_directory, ingest_jsonl
from .rag import RAGAssistant, build_index_from_normalized
from .vector_store import LocalVectorStore

app = typer.Typer(help="Security RAG Assistant")


@app.command()
def ingest(
    raw_path: Path,
    normalized_path: Path = Path("data/processed/normalized.jsonl"),
    append: bool = False,
) -> None:
    """Ingest log files (JSONL, CSV, or a directory of them)."""
    if raw_path.is_dir():
        n = ingest_directory(raw_path, normalized_path, append=append)
    elif raw_path.suffix == ".csv":
        n = ingest_csv(raw_path, normalized_path, append=append)
    else:
        n = ingest_jsonl(raw_path, normalized_path, append=append)
    typer.echo(f"Ingested {n} events to {normalized_path}")


@app.command()
def index(
    normalized_path: Path = Path("data/processed/normalized.jsonl"),
    index_path: Path = Path("data/index"),
    backend: str = "hashing",
    strategy: str = "event",
    window_minutes: int = 5,
) -> None:
    """Build vector index from normalized events."""
    n = build_index_from_normalized(
        normalized_path, index_path,
        backend_name=backend, strategy=strategy, window_minutes=window_minutes,
    )
    typer.echo(f"Indexed {n} chunks into {index_path} (backend={backend}, strategy={strategy})")


@app.command()
def ask(
    query: str,
    host: str | None = None,
    severity: str | None = None,
    hours: int | None = None,
    k: int = 5,
    format: str = "text",
    hybrid_alpha: float = 1.0,
    index_path: Path = Path("data/index"),
    audit_path: Path = Path("data/audit/interactions.jsonl"),
) -> None:
    """Ask a security question against the indexed events."""
    store = LocalVectorStore.load(index_path)
    assistant = RAGAssistant(store)
    result = assistant.query(query, host=host, severity=severity, hours=hours, k=k, hybrid_alpha=hybrid_alpha)

    write_audit_log(audit_path, query=result["query"], evidence=result["evidence"], answer=result["answer"])

    if format == "json":
        typer.echo(json.dumps(result, indent=2))
    else:
        typer.echo("=== Retrieved Evidence ===")
        typer.echo(json.dumps(result["evidence"], indent=2))
        typer.echo("\n=== Generated Answer ===")
        typer.echo(result["answer"])


@app.command()
def watch(
    directory: Path,
    normalized_path: Path = Path("data/processed/normalized.jsonl"),
    poll_interval: int = 5,
) -> None:
    """Watch a directory for new .jsonl/.csv files and auto-ingest them."""
    seen: set[str] = set()
    if directory.exists():
        for f in directory.iterdir():
            if f.suffix in {".jsonl", ".csv"}:
                seen.add(str(f))

    typer.echo(f"Watching {directory} for new log files (poll every {poll_interval}s)...")
    try:
        while True:
            if directory.exists():
                for f in sorted(directory.iterdir()):
                    if f.suffix in {".jsonl", ".csv"} and str(f) not in seen:
                        seen.add(str(f))
                        if f.suffix == ".jsonl":
                            n = ingest_jsonl(f, normalized_path, append=True)
                        else:
                            n = ingest_csv(f, normalized_path, append=True)
                        typer.echo(f"Auto-ingested {n} events from {f.name}")
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        typer.echo("\nWatch stopped.")


@app.command(name="eval")
def evaluate(
    index_path: Path = Path("data/index"),
    golden_path: Path = Path("eval/golden_queries.jsonl"),
    format: str = "text",
) -> None:
    """Run retrieval evaluation against golden queries."""
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
    from eval.evaluate import run_evaluation

    results = run_evaluation(index_path, golden_path)

    if format == "json":
        typer.echo(json.dumps(results, indent=2))
    else:
        metrics = results["metrics"]
        typer.echo("=== Evaluation Results ===")
        typer.echo(f"Queries evaluated: {results['num_queries']}")
        typer.echo(f"Mean Precision@3:  {metrics.get('mean_precision@3', 0):.3f}")
        typer.echo(f"Mean Precision@5:  {metrics.get('mean_precision@5', 0):.3f}")
        typer.echo(f"Mean Recall@5:     {metrics.get('mean_recall@5', 0):.3f}")
        typer.echo(f"Mean MRR:          {metrics['mean_mrr']:.3f}")
        typer.echo(f"Hallucinations:    {metrics['total_hallucinations']}")


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
