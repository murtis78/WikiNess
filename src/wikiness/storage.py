from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from wikiness.models import CVERecord

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cve (
    cve_id                          TEXT PRIMARY KEY,
    title                           TEXT NOT NULL DEFAULT '',
    description                     TEXT NOT NULL DEFAULT '',
    published_date                  TEXT,
    last_modified_date              TEXT,
    cvss_score                      REAL,
    cvss_severity                   TEXT,
    cvss_vector                     TEXT,
    epss_score                      REAL,
    epss_percentile                 REAL,
    kev                             INTEGER NOT NULL DEFAULT 0,
    kev_due_date                    TEXT,
    kev_known_ransomware_campaign_use TEXT,
    kev_required_action             TEXT,
    references_json                 TEXT NOT NULL DEFAULT '[]',
    sources_json                    TEXT NOT NULL DEFAULT '[]',
    public_exploit_available        INTEGER NOT NULL DEFAULT 0,
    poc_count                       INTEGER NOT NULL DEFAULT 0,
    updated_at                      TEXT NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS cve_fts USING fts5(
    cve_id,
    title,
    description,
    references_json,
    content=cve,
    content_rowid=rowid
);

CREATE TRIGGER IF NOT EXISTS cve_ai AFTER INSERT ON cve BEGIN
    INSERT INTO cve_fts(rowid, cve_id, title, description, references_json)
    VALUES (new.rowid, new.cve_id, new.title, new.description, new.references_json);
END;

CREATE TRIGGER IF NOT EXISTS cve_au AFTER UPDATE ON cve BEGIN
    INSERT INTO cve_fts(cve_fts, rowid, cve_id, title, description, references_json)
    VALUES ('delete', old.rowid, old.cve_id, old.title, old.description, old.references_json);
    INSERT INTO cve_fts(rowid, cve_id, title, description, references_json)
    VALUES (new.rowid, new.cve_id, new.title, new.description, new.references_json);
END;

CREATE TRIGGER IF NOT EXISTS cve_ad AFTER DELETE ON cve BEGIN
    INSERT INTO cve_fts(cve_fts, rowid, cve_id, title, description, references_json)
    VALUES ('delete', old.rowid, old.cve_id, old.title, old.description, old.references_json);
END;

CREATE TABLE IF NOT EXISTS sync_state (
    source          TEXT PRIMARY KEY,
    last_sync       TEXT,
    records_synced  INTEGER NOT NULL DEFAULT 0
);
"""


def open_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA)
    for col_ddl in (
        "ALTER TABLE cve ADD COLUMN public_exploit_available INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE cve ADD COLUMN poc_count INTEGER NOT NULL DEFAULT 0",
    ):
        try:
            conn.execute(col_ddl)
        except Exception:
            pass  # column already exists
    conn.commit()


def upsert_cve(conn: sqlite3.Connection, record: CVERecord) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO cve (
            cve_id, title, description, published_date, last_modified_date,
            cvss_score, cvss_severity, cvss_vector,
            epss_score, epss_percentile,
            kev, kev_due_date, kev_known_ransomware_campaign_use, kev_required_action,
            references_json, sources_json, public_exploit_available, poc_count, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
            title = CASE WHEN excluded.title != '' THEN excluded.title ELSE title END,
            description = CASE WHEN excluded.description != '' THEN excluded.description ELSE description END,
            published_date = COALESCE(excluded.published_date, published_date),
            last_modified_date = COALESCE(excluded.last_modified_date, last_modified_date),
            cvss_score = COALESCE(excluded.cvss_score, cvss_score),
            cvss_severity = COALESCE(excluded.cvss_severity, cvss_severity),
            cvss_vector = COALESCE(excluded.cvss_vector, cvss_vector),
            epss_score = COALESCE(excluded.epss_score, epss_score),
            epss_percentile = COALESCE(excluded.epss_percentile, epss_percentile),
            kev = MAX(excluded.kev, kev),
            kev_due_date = COALESCE(excluded.kev_due_date, kev_due_date),
            kev_known_ransomware_campaign_use = COALESCE(
                excluded.kev_known_ransomware_campaign_use, kev_known_ransomware_campaign_use
            ),
            kev_required_action = COALESCE(excluded.kev_required_action, kev_required_action),
            references_json = CASE
                WHEN excluded.references_json != '[]' THEN excluded.references_json
                ELSE references_json
            END,
            sources_json = CASE
                WHEN excluded.sources_json != '[]' THEN excluded.sources_json
                ELSE sources_json
            END,
            public_exploit_available = MAX(excluded.public_exploit_available, public_exploit_available),
            poc_count = MAX(excluded.poc_count, poc_count),
            updated_at = excluded.updated_at
        """,
        (
            record.cve_id,
            record.title,
            record.description,
            record.published_date,
            record.last_modified_date,
            record.cvss_score,
            record.cvss_severity,
            record.cvss_vector,
            record.epss_score,
            record.epss_percentile,
            1 if record.kev else 0,
            record.kev_due_date,
            record.kev_known_ransomware_campaign_use,
            record.kev_required_action,
            json.dumps(record.references),
            json.dumps(record.sources),
            1 if record.public_exploit_available else 0,
            record.poc_count,
            now,
        ),
    )
    conn.commit()


def get_cve(conn: sqlite3.Connection, cve_id: str) -> Optional[CVERecord]:
    row = conn.execute("SELECT * FROM cve WHERE cve_id = ?", (cve_id.upper(),)).fetchone()
    if row is None:
        return None
    return _row_to_record(row)


def _row_to_record(row: sqlite3.Row) -> CVERecord:
    return CVERecord(
        cve_id=row["cve_id"],
        title=row["title"],
        description=row["description"],
        published_date=row["published_date"],
        last_modified_date=row["last_modified_date"],
        cvss_score=row["cvss_score"],
        cvss_severity=row["cvss_severity"],
        cvss_vector=row["cvss_vector"],
        epss_score=row["epss_score"],
        epss_percentile=row["epss_percentile"],
        kev=bool(row["kev"]),
        kev_due_date=row["kev_due_date"],
        kev_known_ransomware_campaign_use=row["kev_known_ransomware_campaign_use"],
        kev_required_action=row["kev_required_action"],
        references=json.loads(row["references_json"]),
        sources=json.loads(row["sources_json"]),
        public_exploit_available=bool(row["public_exploit_available"]),
        poc_count=row["poc_count"] or 0,
    )


def update_sync_state(conn: sqlite3.Connection, source: str, records_synced: int) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO sync_state (source, last_sync, records_synced)
        VALUES (?, ?, ?)
        ON CONFLICT(source) DO UPDATE SET
            last_sync = excluded.last_sync,
            records_synced = excluded.records_synced
        """,
        (source, now, records_synced),
    )
    conn.commit()


def get_sync_state(conn: sqlite3.Connection, source: str) -> Optional[dict]:
    row = conn.execute("SELECT * FROM sync_state WHERE source = ?", (source,)).fetchone()
    if row is None:
        return None
    return {
        "source": row["source"],
        "last_sync": row["last_sync"],
        "records_synced": row["records_synced"],
    }


def get_all_cve_ids(conn: sqlite3.Connection) -> list[str]:
    return [row["cve_id"] for row in conn.execute("SELECT cve_id FROM cve").fetchall()]


def count_cves(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
