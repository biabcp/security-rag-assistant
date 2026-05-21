"""Configuration management for the Security RAG Assistant."""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class Config:
    """Application configuration loaded from env vars and/or config file."""

    data_dir: str = "data"
    normalized_path: str = "data/processed/normalized.jsonl"
    index_path: str = "data/index"
    audit_path: str = "data/audit/interactions.jsonl"

    embedding_backend: str = "hashing"
    chunking_strategy: str = "event"
    window_minutes: int = 5

    llm_provider: str = "rule"
    openai_model: str = "gpt-4o-mini"
    ollama_model: str = "llama3"
    ollama_base_url: str = "http://localhost:11434"

    api_host: str = "0.0.0.0"
    api_port: int = 8000

    top_k: int = 5
    hybrid_alpha: float = 1.0

    log_level: str = "INFO"
    log_format: str = "json"

    @classmethod
    def load(cls, config_path: Path | None = None) -> "Config":
        """Load config from file (if exists) then overlay environment variables."""
        values: dict[str, Any] = {}

        if config_path and config_path.exists():
            with config_path.open() as f:
                values.update(json.load(f))

        default_config = Path("config.yaml")
        if not config_path and default_config.exists():
            import json as _json
            try:
                with default_config.open() as f:
                    values.update(_json.load(f))
            except (json.JSONDecodeError, ValueError):
                pass

        env_mapping = {
            "SECURITY_RAG_DATA_DIR": "data_dir",
            "SECURITY_RAG_EMBEDDING_BACKEND": "embedding_backend",
            "SECURITY_RAG_CHUNKING_STRATEGY": "chunking_strategy",
            "SECURITY_RAG_LLM_PROVIDER": "llm_provider",
            "SECURITY_RAG_TOP_K": "top_k",
            "SECURITY_RAG_HYBRID_ALPHA": "hybrid_alpha",
            "SECURITY_RAG_LOG_LEVEL": "log_level",
            "SECURITY_RAG_LOG_FORMAT": "log_format",
            "SECURITY_RAG_API_HOST": "api_host",
            "SECURITY_RAG_API_PORT": "api_port",
            "OPENAI_MODEL": "openai_model",
            "OLLAMA_MODEL": "ollama_model",
            "OLLAMA_BASE_URL": "ollama_base_url",
        }

        for env_var, field_name in env_mapping.items():
            val = os.environ.get(env_var)
            if val is not None:
                values[field_name] = val

        int_fields = {"top_k", "window_minutes", "api_port"}
        float_fields = {"hybrid_alpha"}
        for k, v in values.items():
            if k in int_fields and isinstance(v, str):
                values[k] = int(v)
            elif k in float_fields and isinstance(v, str):
                values[k] = float(v)

        return cls(**{k: v for k, v in values.items() if hasattr(cls, k)})


def setup_logging(config: Config | None = None) -> None:
    """Configure structured JSON logging."""
    level = getattr(logging, (config.log_level if config else "INFO").upper(), logging.INFO)

    if config and config.log_format == "json":
        formatter = logging.Formatter(
            json.dumps({
                "time": "%(asctime)s",
                "level": "%(levelname)s",
                "module": "%(module)s",
                "message": "%(message)s",
            })
        )
    else:
        formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(module)s: %(message)s")

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    root = logging.getLogger("security_rag")
    root.setLevel(level)
    root.handlers = [handler]
