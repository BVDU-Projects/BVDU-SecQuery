"""Local SQLite hash intelligence and portable signature packs."""
import csv
import json
import os
import sqlite3
from pathlib import Path
from typing import Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS signatures (
  sha256 TEXT PRIMARY KEY, md5 TEXT, name TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'high', source TEXT NOT NULL DEFAULT 'local-pack',
  added_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_signatures_md5 ON signatures(md5);
CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS known_file_cache (
  md5 TEXT PRIMARY KEY, metadata_json TEXT, checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


def default_db_path() -> Path:
    override = os.environ.get("SECQUERY_DB")
    if override:
        return Path(override).expanduser()
    from .engines import app_data_dir
    return app_data_dir() / "signatures.sqlite3"


class SignatureDB:
    def __init__(self, path: Path | str | None = None):
        self.path = Path(path) if path else default_db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def close(self):
        self.conn.close()

    def lookup(self, sha256: str, md5: str) -> list[tuple[str, str, str]]:
        rows = self.conn.execute(
            "SELECT name,severity,source FROM signatures "
            "WHERE (sha256=? OR (? != '' AND md5=?)) "
            "AND (source != 'ThreatFox' OR added_at >= datetime('now', '-180 days'))",
            (sha256, md5, md5),
        ).fetchall()
        return rows

    def add(self, sha256: str, md5: str, name: str, severity: str = "high", source: str = "local-pack"):
        self.conn.execute(
            "INSERT INTO signatures(sha256,md5,name,severity,source) VALUES(?,?,?,?,?) "
            "ON CONFLICT(sha256) DO UPDATE SET md5=excluded.md5,name=excluded.name,"
            "severity=excluded.severity,source=excluded.source,added_at=CURRENT_TIMESTAMP",
            (sha256.lower(), md5.lower(), name, severity.lower(), source),
        )

    def add_many(self, rows: Iterable[dict], *, source: str = "local-pack") -> int:
        count = 0
        for row in rows:
            sha = str(row.get("sha256", "")).lower().strip()
            md5 = str(row.get("md5", "")).lower().strip()
            name = str(row.get("name", "Unspecified signature")).strip()[:200]
            severity = str(row.get("severity", "high")).lower().strip()
            if not _hex_digest(sha, 64) or (md5 and not _hex_digest(md5, 32)):
                raise ValueError("Signature pack contains an invalid SHA-256 or MD5 digest")
            if severity not in {"low", "medium", "high", "critical"}:
                raise ValueError(f"Invalid severity: {severity}")
            if source == "ThreatFox":
                existing = self.conn.execute(
                    "SELECT source FROM signatures WHERE sha256=?", (sha,)
                ).fetchone()
                if existing and existing[0] != "ThreatFox":
                    # Never let an expiring network IOC replace a durable imported/local record.
                    count += 1
                    continue
            self.add(sha, md5, name or "Unspecified signature", severity, source)
            count += 1
        self.conn.commit()
        return count

    def signature_count(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM signatures").fetchone()[0])

    def prune_source(self, source: str, *, older_than_days: int) -> int:
        cursor = self.conn.execute(
            "DELETE FROM signatures WHERE source=? AND added_at < datetime('now', ?)",
            (source, f"-{older_than_days} days"),
        )
        self.conn.commit()
        return cursor.rowcount

    def known_file_cache_get(self, md5: str, *, max_age_days: int = 30):
        row = self.conn.execute(
            "SELECT metadata_json FROM known_file_cache WHERE md5=? "
            "AND checked_at >= datetime('now', ?)",
            (md5, f"-{max_age_days} days"),
        ).fetchone()
        return None if row is None else json.loads(row[0]) if row[0] is not None else {}

    def known_file_cache_set(self, md5: str, metadata: dict | None):
        encoded = json.dumps(metadata, ensure_ascii=True, separators=(",", ":")) if metadata else None
        self.conn.execute(
            "INSERT INTO known_file_cache(md5,metadata_json,checked_at) VALUES(?,?,CURRENT_TIMESTAMP) "
            "ON CONFLICT(md5) DO UPDATE SET metadata_json=excluded.metadata_json,checked_at=CURRENT_TIMESTAMP",
            (md5, encoded),
        )
        self.conn.commit()

    def export_pack(self, output: Path | str):
        rows = self.conn.execute(
            "SELECT sha256,md5,name,severity FROM signatures ORDER BY sha256"
        ).fetchall()
        pack = {"format": "bvdu-secquery-signatures", "version": 1, "signatures": [
            dict(zip(("sha256", "md5", "name", "severity"), row)) for row in rows
        ]}
        Path(output).write_text(json.dumps(pack, indent=2) + "\n", encoding="utf-8")
        return len(rows)

    def import_pack(self, source: Path | str):
        path = Path(source)
        if path.suffix.lower() == ".csv":
            with path.open(newline="", encoding="utf-8-sig") as handle:
                return self.add_many(csv.DictReader(handle))
        pack = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(pack, dict) or pack.get("format") != "bvdu-secquery-signatures" or pack.get("version") != 1:
            raise ValueError("Unsupported signature pack format")
        rows = pack.get("signatures")
        if not isinstance(rows, list) or len(rows) > 1_000_000:
            raise ValueError("Signature list is invalid or exceeds the 1,000,000 entry limit")
        return self.add_many(rows)


def _hex_digest(value: str, length: int) -> bool:
    return len(value) == length and all(c in "0123456789abcdef" for c in value)
