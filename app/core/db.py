"""SQLite metadata store.

A thin wrapper around stdlib `sqlite3`. We deliberately avoid SQLAlchemy
here so the module stays trivially auditable for a security prototype.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Iterator, Optional

from .config import get_settings


DDL = [
    """
    CREATE TABLE IF NOT EXISTS documents (
        doc_id TEXT PRIMARY KEY,
        title TEXT,
        source TEXT,
        source_type TEXT,
        published_date TEXT,
        ingested_at TEXT,
        trust_score REAL,
        file_path TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS chunks (
        chunk_id TEXT PRIMARY KEY,
        doc_id TEXT,
        text TEXT,
        start_char INTEGER,
        end_char INTEGER,
        metadata TEXT,
        FOREIGN KEY(doc_id) REFERENCES documents(doc_id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS stix_entities (
        entity_id TEXT PRIMARY KEY,
        doc_id TEXT,
        stix_type TEXT,
        name TEXT,
        value TEXT,
        confidence REAL,
        evidence TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS stix_relationships (
        relationship_id TEXT PRIMARY KEY,
        doc_id TEXT,
        source_entity TEXT,
        relationship_type TEXT,
        target_entity TEXT,
        confidence REAL,
        evidence TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS attack_mappings (
        technique_id TEXT,
        doc_id TEXT,
        technique_name TEXT,
        tactic TEXT,
        confidence REAL,
        evidence TEXT,
        PRIMARY KEY(technique_id, doc_id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS generated_rules (
        rule_id TEXT PRIMARY KEY,
        doc_id TEXT,
        rule_type TEXT,
        title TEXT,
        rule_text TEXT,
        attack_technique TEXT,
        confidence REAL,
        evidence TEXT,
        created_at TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS validation_results (
        validation_id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_id TEXT,
        syntax_valid INTEGER,
        semantic_valid INTEGER,
        malicious_hits INTEGER,
        malicious_total INTEGER,
        benign_hits INTEGER,
        benign_total INTEGER,
        false_positive_rate REAL,
        final_verdict TEXT,
        warnings TEXT
    );
    """,
]


def _connect(path: Optional[Path] = None) -> sqlite3.Connection:
    path = path or get_settings().db_path
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(path: Optional[Path] = None) -> None:
    with _connect(path) as conn:
        for stmt in DDL:
            conn.execute(stmt)
        conn.commit()


@contextmanager
def get_conn(path: Optional[Path] = None) -> Iterator[sqlite3.Connection]:
    init_db(path)
    conn = _connect(path)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------


def upsert_document(doc: dict) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO documents (doc_id, title, source, source_type,
                                   published_date, ingested_at, trust_score, file_path)
            VALUES (?,?,?,?,?,?,?,?)
            ON CONFLICT(doc_id) DO UPDATE SET
                title=excluded.title, source=excluded.source,
                source_type=excluded.source_type,
                published_date=excluded.published_date,
                trust_score=excluded.trust_score,
                file_path=excluded.file_path
            """,
            (
                doc["doc_id"],
                doc.get("title"),
                doc.get("source"),
                doc.get("source_type"),
                doc.get("published_date"),
                doc.get("ingested_at"),
                doc.get("trust_score"),
                doc.get("file_path"),
            ),
        )


def upsert_chunks(chunks: Iterable[dict]) -> None:
    with get_conn() as conn:
        for c in chunks:
            conn.execute(
                """
                INSERT OR REPLACE INTO chunks
                    (chunk_id, doc_id, text, start_char, end_char, metadata)
                VALUES (?,?,?,?,?,?)
                """,
                (
                    c["chunk_id"],
                    c["doc_id"],
                    c["text"],
                    c["start_char"],
                    c["end_char"],
                    json.dumps(c.get("metadata", {})),
                ),
            )


def get_document(doc_id: str) -> Optional[dict]:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM documents WHERE doc_id=?", (doc_id,)
        ).fetchone()
        return dict(row) if row else None


def get_chunks(doc_id: str) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM chunks WHERE doc_id=? ORDER BY start_char", (doc_id,)
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["metadata"] = json.loads(d.get("metadata") or "{}")
            except Exception:
                d["metadata"] = {}
            out.append(d)
        return out


def all_chunks() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM chunks").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["metadata"] = json.loads(d.get("metadata") or "{}")
            except Exception:
                d["metadata"] = {}
            out.append(d)
        return out


def list_documents() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM documents ORDER BY ingested_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]
