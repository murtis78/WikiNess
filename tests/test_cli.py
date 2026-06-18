import json
import socket

import pytest
from typer.testing import CliRunner

from wikiness.cli import app
from wikiness.models import CVERecord
from wikiness.storage import init_schema, open_db, upsert_cve

runner = CliRunner()


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "test.db"
    conn = open_db(path)
    init_schema(conn)
    upsert_cve(
        conn,
        CVERecord(
            cve_id="CVE-2024-99001",
            title="Apache HTTP Server RCE",
            description="Critical remote code execution vulnerability in Apache HTTP Server.",
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
        conn,
        CVERecord(
            cve_id="CVE-2024-99002",
            title="WordPress SQL Injection",
            description="SQL injection vulnerability in WordPress plugin allows database access.",
            cvss_score=6.5,
            cvss_severity="MEDIUM",
            kev=False,
            epss_score=0.01,
            epss_percentile=0.65,
            sources=["NVD"],
        ),
    )
    conn.close()
    return path


def test_search_json_valid(db_path):
    r = runner.invoke(app, ["--db", str(db_path), "--json", "search", "apache"])
    assert r.exit_code == 0
    data = json.loads(r.output)
    assert isinstance(data, list)


def test_search_returns_matching_cve(db_path):
    r = runner.invoke(app, ["--db", str(db_path), "--json", "search", "apache"])
    assert r.exit_code == 0
    data = json.loads(r.output)
    assert data[0]["cve_id"] == "CVE-2024-99001"


def test_search_kev_only_flag(db_path):
    r = runner.invoke(app, ["--db", str(db_path), "--json", "search", "vulnerability", "--kev-only"])
    assert r.exit_code == 0
    data = json.loads(r.output)
    assert all(item["kev"] for item in data)


def test_search_min_epss_filter(db_path):
    r = runner.invoke(app, ["--db", str(db_path), "--json", "search", "vulnerability", "--min-epss", "0.5"])
    assert r.exit_code == 0
    data = json.loads(r.output)
    assert all(item["epss_score"] >= 0.5 for item in data)


def test_show_json_valid(db_path):
    r = runner.invoke(app, ["--db", str(db_path), "--json", "show", "CVE-2024-99001"])
    assert r.exit_code == 0
    data = json.loads(r.output)
    assert data["cve_id"] == "CVE-2024-99001"
    assert data["kev"] is True
    assert "priority" in data


def test_show_includes_priority_components(db_path):
    r = runner.invoke(app, ["--db", str(db_path), "--json", "show", "CVE-2024-99001"])
    data = json.loads(r.output)
    p = data["priority"]
    assert "final_score" in p
    assert "base_cvss" in p
    assert "kev_boost" in p
    assert "epss_boost" in p
    assert "reason" in p


def test_show_not_found_exits_1(db_path):
    r = runner.invoke(app, ["--db", str(db_path), "show", "CVE-9999-00000"])
    assert r.exit_code == 1


def test_prioritize_json_valid(db_path):
    r = runner.invoke(app, ["--db", str(db_path), "--json", "prioritize"])
    assert r.exit_code == 0
    data = json.loads(r.output)
    assert isinstance(data, list)
    assert len(data) >= 1


def test_prioritize_ordered_by_score(db_path):
    r = runner.invoke(app, ["--db", str(db_path), "--json", "prioritize"])
    data = json.loads(r.output)
    scores = [item["priority"]["final_score"] for item in data]
    assert scores == sorted(scores, reverse=True)


def test_prioritize_kev_only(db_path):
    r = runner.invoke(app, ["--db", str(db_path), "--json", "prioritize", "--kev-only"])
    assert r.exit_code == 0
    data = json.loads(r.output)
    assert all(item["kev"] for item in data)


def test_stats_json_valid(db_path):
    r = runner.invoke(app, ["--db", str(db_path), "--json", "stats"])
    assert r.exit_code == 0
    data = json.loads(r.output)
    assert data["total_cves"] == 2
    assert data["kev_count"] == 1
    assert data["critical_count"] == 1
    assert "high_count" in data
    assert data["high_count"] == 0


def test_stats_high_severity_count(tmp_path):
    path = tmp_path / "test.db"
    conn = open_db(path)
    init_schema(conn)
    upsert_cve(
        conn,
        CVERecord(
            cve_id="CVE-2024-88001",
            title="High Severity Test",
            description="High severity test CVE.",
            cvss_score=7.5,
            cvss_severity="HIGH",
            kev=False,
            sources=["NVD"],
        ),
    )
    conn.close()
    r = runner.invoke(app, ["--db", str(path), "--json", "stats"])
    assert r.exit_code == 0
    data = json.loads(r.output)
    assert data["high_count"] == 1


def test_search_no_network(db_path, monkeypatch):
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("no network")))
    r = runner.invoke(app, ["--db", str(db_path), "--json", "search", "apache"])
    assert r.exit_code == 0


def test_show_no_network(db_path, monkeypatch):
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("no network")))
    r = runner.invoke(app, ["--db", str(db_path), "--json", "show", "CVE-2024-99001"])
    assert r.exit_code == 0


def test_prioritize_no_network(db_path, monkeypatch):
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("no network")))
    r = runner.invoke(app, ["--db", str(db_path), "--json", "prioritize"])
    assert r.exit_code == 0


def test_sync_poc_enriches_db(db_path, monkeypatch):
    import wikiness.ingest.poc as poc_module

    monkeypatch.setattr(
        poc_module,
        "enrich_with_poc",
        lambda cve_ids: {
            cve_id: {"public_exploit_available": True, "poc_count": 1} for cve_id in cve_ids
        },
    )

    r = runner.invoke(app, ["--db", str(db_path), "sync", "poc"])
    assert r.exit_code == 0
    assert "PoC sync complete" in r.output


def test_show_displays_poc_field(db_path):
    r = runner.invoke(app, ["--db", str(db_path), "show", "CVE-2024-99001"])
    assert r.exit_code == 0
    assert "Public Exploit" in r.output


def test_show_json_includes_poc_fields(db_path):
    r = runner.invoke(app, ["--db", str(db_path), "--json", "show", "CVE-2024-99001"])
    assert r.exit_code == 0
    data = json.loads(r.output)
    assert "public_exploit_available" in data
    assert "poc_count" in data


def _add_poc_cve(db_path):
    conn = open_db(db_path)
    init_schema(conn)
    upsert_cve(
        conn,
        CVERecord(
            cve_id="CVE-2024-88001",
            title="Known Exploit Vulnerability",
            description="This vulnerability has a known public exploit available.",
            cvss_score=8.0,
            public_exploit_available=True,
            poc_count=2,
            sources=["NVD"],
        ),
    )
    conn.close()


def test_search_poc_only_flag(db_path):
    _add_poc_cve(db_path)
    r = runner.invoke(app, ["--db", str(db_path), "--json", "search", "vulnerability", "--poc-only"])
    assert r.exit_code == 0
    data = json.loads(r.output)
    assert len(data) >= 1
    assert all(item["public_exploit_available"] for item in data)
    assert not any(item["cve_id"] in {"CVE-2024-99001", "CVE-2024-99002"} for item in data)


def test_prioritize_poc_only_flag(db_path):
    _add_poc_cve(db_path)
    r = runner.invoke(app, ["--db", str(db_path), "--json", "prioritize", "--poc-only"])
    assert r.exit_code == 0
    data = json.loads(r.output)
    assert len(data) >= 1
    assert all(item["public_exploit_available"] for item in data)


def test_search_table_has_poc_column(db_path):
    r = runner.invoke(app, ["--db", str(db_path), "search", "apache"])
    assert r.exit_code == 0
    assert "PoC" in r.output


# WN-011 — --format markdown tests


def test_show_format_markdown_heading(db_path):
    r = runner.invoke(app, ["--db", str(db_path), "show", "CVE-2024-99001", "--format", "markdown"])
    assert r.exit_code == 0
    assert "# CVE-2024-99001" in r.output


def test_show_format_markdown_cvss_scores(db_path):
    r = runner.invoke(app, ["--db", str(db_path), "show", "CVE-2024-99001", "--format", "markdown"])
    assert r.exit_code == 0
    assert "9.8" in r.output
    assert "CRITICAL" in r.output


def test_show_format_markdown_kev_poc(db_path):
    r = runner.invoke(app, ["--db", str(db_path), "show", "CVE-2024-99001", "--format", "markdown"])
    assert r.exit_code == 0
    assert "KEV" in r.output
    assert "YES" in r.output


def test_show_format_markdown_priority_reason(db_path):
    r = runner.invoke(app, ["--db", str(db_path), "show", "CVE-2024-99001", "--format", "markdown"])
    assert r.exit_code == 0
    assert "Priority" in r.output
    assert "Reason" in r.output


def test_show_format_table_default_regression(db_path):
    r = runner.invoke(app, ["--db", str(db_path), "show", "CVE-2024-99001"])
    assert r.exit_code == 0
    assert "Public Exploit" in r.output
    assert "# CVE-2024-99001" not in r.output


def test_show_format_markdown_no_network(db_path, monkeypatch):
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("no network")))
    r = runner.invoke(app, ["--db", str(db_path), "show", "CVE-2024-99001", "--format", "markdown"])
    assert r.exit_code == 0
    assert "# CVE-2024-99001" in r.output


def test_show_format_invalid_errors(db_path):
    r = runner.invoke(app, ["--db", str(db_path), "show", "CVE-2024-99001", "--format", "xml"])
    assert r.exit_code == 1
    assert "table" in r.output or "markdown" in r.output


def test_show_json_format_mutually_exclusive(db_path):
    r = runner.invoke(app, ["--db", str(db_path), "--json", "show", "CVE-2024-99001", "--format", "markdown"])
    assert r.exit_code == 1
    assert "mutually exclusive" in r.output.lower()


# WN-004 — --since-modified CLI tests


def test_sync_nvd_since_modified_accepted(tmp_path, monkeypatch):
    """--since-modified is accepted and completes without a live network call."""
    monkeypatch.setattr("wikiness.ingest.nvd.iter_nvd_pages", lambda **kw: iter([]))
    r = runner.invoke(app, ["--db", str(tmp_path / "test.db"), "sync", "nvd", "--since-modified", "2026-06-01"])
    assert r.exit_code == 0


def test_sync_nvd_since_and_since_modified_mutually_exclusive(tmp_path):
    """--since and --since-modified together must exit with code 1."""
    r = runner.invoke(
        app,
        [
            "--db", str(tmp_path / "test.db"),
            "sync", "nvd",
            "--since", "2026-06-01",
            "--since-modified", "2026-06-01",
        ],
    )
    assert r.exit_code == 1
