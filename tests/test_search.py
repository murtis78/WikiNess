import socket

import pytest

from wikiness.models import CVERecord
from wikiness.scoring import compute_priority
from wikiness.search import fts_search, prioritized_list
from wikiness.storage import get_cve, upsert_cve


def _populate(db):
    upsert_cve(
        db,
        CVERecord(
            cve_id="CVE-2024-99001",
            title="Apache HTTP Server RCE",
            description="A critical remote code execution vulnerability in Apache HTTP Server mod_proxy.",
            cvss_score=9.8,
            cvss_severity="CRITICAL",
            kev=True,
            epss_score=0.97,
            epss_percentile=0.9998,
            references=["https://httpd.apache.org/security/vulnerabilities_24.html"],
            sources=["NVD", "CISA_KEV"],
        ),
    )
    upsert_cve(
        db,
        CVERecord(
            cve_id="CVE-2024-99002",
            title="WordPress SQL Injection",
            description="An SQL injection vulnerability in a WordPress plugin allows database access.",
            cvss_score=6.5,
            cvss_severity="MEDIUM",
            kev=False,
            epss_score=0.01,
            epss_percentile=0.65,
            sources=["NVD"],
        ),
    )


def test_fts_search_keyword_match(db):
    _populate(db)
    results = fts_search(db, "apache")
    assert len(results) == 1
    assert results[0].cve_id == "CVE-2024-99001"


def test_fts_search_cve_id_lookup(db):
    _populate(db)
    results = fts_search(db, "CVE-2024-99001")
    assert len(results) == 1
    assert results[0].cve_id == "CVE-2024-99001"


def test_fts_search_cve_id_case_insensitive(db):
    _populate(db)
    results = fts_search(db, "cve-2024-99001")
    assert len(results) == 1


def test_fts_search_returns_expected_fields(db):
    _populate(db)
    r = fts_search(db, "apache")[0]
    assert r.cvss_score == 9.8
    assert r.kev is True
    assert r.epss_score == pytest.approx(0.97)


def test_fts_search_kev_only_filter(db):
    _populate(db)
    results = fts_search(db, "vulnerability", kev_only=True)
    assert all(r.kev for r in results)


def test_fts_search_min_epss_filter(db):
    _populate(db)
    results = fts_search(db, "vulnerability", min_epss=0.5)
    assert all(r.epss_score >= 0.5 for r in results)


def test_fts_search_limit(db):
    _populate(db)
    results = fts_search(db, "vulnerability", limit=1)
    assert len(results) <= 1


def test_fts_search_no_results(db):
    _populate(db)
    results = fts_search(db, "xyznotpresent")
    assert results == []


def test_fts_search_does_not_use_network(db, monkeypatch):
    _populate(db)
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("no network")))
    results = fts_search(db, "apache")
    assert len(results) >= 1


def test_prioritize_kev_ranks_above_non_kev(db):
    _populate(db)
    results = prioritized_list(db)
    assert len(results) >= 2
    kev_pos = next(i for i, (r, _) in enumerate(results) if r.kev)
    non_kev_pos = next(i for i, (r, _) in enumerate(results) if not r.kev)
    assert kev_pos < non_kev_pos


def test_prioritize_ordered_descending(db):
    _populate(db)
    results = prioritized_list(db)
    scores = [s.final_score for _, s in results]
    assert scores == sorted(scores, reverse=True)


def test_prioritize_kev_only_filter(db):
    _populate(db)
    results = prioritized_list(db, kev_only=True)
    assert all(r.kev for r, _ in results)


def test_prioritize_does_not_use_network(db, monkeypatch):
    _populate(db)
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("no network")))
    results = prioritized_list(db)
    assert len(results) >= 1


def test_show_does_not_use_network(db, monkeypatch):
    _populate(db)
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("no network")))
    r = get_cve(db, "CVE-2024-99001")
    assert r is not None
    score = compute_priority(r)
    assert score.final_score > 0


# PoC filter tests


def _populate_poc(db):
    """One CVE with PoC, one without."""
    upsert_cve(
        db,
        CVERecord(
            cve_id="CVE-2024-88001",
            title="Exploit available vulnerability",
            description="Vulnerability with known public exploit available.",
            cvss_score=8.0,
            public_exploit_available=True,
            poc_count=3,
            sources=["NVD"],
        ),
    )
    upsert_cve(
        db,
        CVERecord(
            cve_id="CVE-2024-88002",
            title="No exploit vulnerability",
            description="Vulnerability without known public exploit.",
            cvss_score=7.0,
            public_exploit_available=False,
            poc_count=0,
            sources=["NVD"],
        ),
    )


def test_fts_search_poc_only_filter(db):
    _populate_poc(db)
    results = fts_search(db, "vulnerability", poc_only=True)
    assert all(r.public_exploit_available for r in results)
    assert any(r.cve_id == "CVE-2024-88001" for r in results)
    assert all(r.cve_id != "CVE-2024-88002" for r in results)


def test_prioritized_list_poc_only_filter(db):
    _populate_poc(db)
    results = prioritized_list(db, poc_only=True)
    assert all(r.public_exploit_available for r, _ in results)
    assert len(results) == 1
    assert results[0][0].cve_id == "CVE-2024-88001"


def test_fts_search_poc_only_cve_id_path(db):
    _populate_poc(db)
    assert fts_search(db, "CVE-2024-88002", poc_only=True) == []
    results = fts_search(db, "CVE-2024-88001", poc_only=True)
    assert len(results) == 1 and results[0].cve_id == "CVE-2024-88001"


def test_poc_only_composes_with_kev_only(db):
    """Condition 1 — poc_only + kev_only compose : retourne seulement KEV+PoC."""
    upsert_cve(
        db,
        CVERecord(
            cve_id="CVE-2024-88003",
            title="KEV and PoC vulnerability",
            description="Both KEV flag and public exploit present vulnerability.",
            kev=True,
            public_exploit_available=True,
            poc_count=1,
            sources=["NVD"],
        ),
    )
    _populate_poc(db)
    results = fts_search(db, "vulnerability", poc_only=True, kev_only=True)
    assert all(r.kev and r.public_exploit_available for r in results)
    assert any(r.cve_id == "CVE-2024-88003" for r in results)
    assert all(r.cve_id not in {"CVE-2024-88001", "CVE-2024-88002"} for r in results)
    results_p = prioritized_list(db, poc_only=True, kev_only=True)
    assert all(r.kev and r.public_exploit_available for r, _ in results_p)
