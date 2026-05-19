"""Central configuration for VeriCTI-RAG.

All paths and tunables live here so tests and notebooks can override them
via environment variables without code changes.
"""

from __future__ import annotations

import os
from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


_REPO_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="VERICTI_",
        env_file=".env",
        extra="ignore",
    )

    # Filesystem layout
    data_dir: Path = Field(default=_REPO_ROOT / "data")
    db_path: Path = Field(default=_REPO_ROOT / "data" / "vericti.db")
    chroma_dir: Path = Field(default=_REPO_ROOT / "data" / "chroma")
    prompts_dir: Path = Field(default=_REPO_ROOT / "prompts")

    # Chunking
    chunk_size: int = 600  # characters
    chunk_overlap: int = 100  # characters

    # Retrieval
    top_k: int = 6
    hybrid_alpha: float = 0.5  # weight of vector vs. BM25

    # LLM abstraction
    llm_provider: str = "mock"  # mock | openai | anthropic
    llm_model: str = "gpt-4o-mini"
    embedding_model: str = "all-MiniLM-L6-v2"

    # Trust & freshness
    default_trust_score: float = 0.6
    freshness_half_life_days: int = 180

    # Confidence weights (must sum to 1.0)
    w_evidence: float = 0.35
    w_trust: float = 0.15
    w_freshness: float = 0.15
    w_graph: float = 0.15
    w_validation: float = 0.20

    def ensure_dirs(self) -> None:
        for sub in [
            "raw_reports",
            "poisoned_reports",
            "logs_malicious",
            "logs_benign",
            "ground_truth",
            "chunks",
            "uploads",
        ]:
            (self.data_dir / sub).mkdir(parents=True, exist_ok=True)
        self.chroma_dir.mkdir(parents=True, exist_ok=True)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.prompts_dir.mkdir(parents=True, exist_ok=True)


settings = Settings()
settings.ensure_dirs()


def get_settings() -> Settings:
    return settings
