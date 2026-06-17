from __future__ import annotations

import re
import sqlite3
from typing import Optional

from wikiness.models import CVERecord
from wikiness.scoring import PriorityScore, compute_priority
from wikiness.storage import _row_to_record, get_cve

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)


def _sanitize_query(query: str) -> str:
    if _CVE_ID_RE.match(query):
        return f'"{query}"'
    return query


def fts_search(
    conn: sqlite3.Connection,
    query: str,
    limit: int = 20,
    kev_only: bool = False,
    min_epss: Optional[float] = None,
    poc_only: bool = False,
) -> list[CVERecord]:
    if _CVE_ID_RE.match(query):
        record = get_cve(conn, query.upper())
        if record is None:
            return []
        if kev_only and not record.kev:
            return []
        if min_epss is not None and (record.epss_score is None or record.epss_score < min_epss):
            return []
        if poc_only and not record.public_exploit_available:
            return []
        return [record]

    sql = "SELECT * FROM cve WHERE rowid IN (SELECT rowid FROM cve_fts WHERE cve_fts MATCH ?)"
    params: list = [_sanitize_query(query)]

    if kev_only:
        sql += " AND kev = 1"
    if min_epss is not None:
        sql += " AND epss_score >= ?"
        params.append(min_epss)
    if poc_only:
        sql += " AND public_exploit_available = 1"

    sql += " LIMIT ?"
    params.append(limit)

    try:
        rows = conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        return []

    return [_row_to_record(row) for row in rows]


def prioritized_list(
    conn: sqlite3.Connection,
    limit: int = 50,
    kev_only: bool = False,
    min_epss: Optional[float] = None,
    poc_only: bool = False,
) -> list[tuple[CVERecord, PriorityScore]]:
    sql = "SELECT * FROM cve WHERE 1=1"
    params: list = []

    if kev_only:
        sql += " AND kev = 1"
    if min_epss is not None:
        sql += " AND epss_score >= ?"
        params.append(min_epss)
    if poc_only:
        sql += " AND public_exploit_available = 1"

    rows = conn.execute(sql, params).fetchall()
    records = [_row_to_record(row) for row in rows]

    scored = [(r, compute_priority(r)) for r in records]
    scored.sort(key=lambda x: x[1].final_score, reverse=True)
    return scored[:limit]
