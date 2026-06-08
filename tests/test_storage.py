import pytest

from wikiness.models import CVERecord
from wikiness.storage import (
    count_cves,
    get_all_cve_ids,
    get_cve,
    get_sync_state,
    update_sync_state,
    upsert_cve,
)


def _cve(**kwargs) -> CVERecord:
    defaults = dict(
        cve_id="CVE-2024-99001",
        title="Test CVE",
        description="A test vulnerability in test software.",
        published_date="2024-01-01T00:00:00.000",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
    )
    defaults.update(kwargs)
    return CVERecord(**defaults)


def test_schema_creates_cve_table(db):
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert "cve" in tables


def test_schema_creates_sync_state_table(db):
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert "sync_state" in tables


def test_schema_creates_fts_table(db):
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert "cve_fts" in tables


def test_insert_cve(db):
    upsert_cve(db, _cve())
    assert count_cves(db) == 1


def test_get_cve_returns_record(db):
    upsert_cve(db, _cve(description="Remote code execution in Apache"))
    r = get_cve(db, "CVE-2024-99001")
    assert r is not None
    assert r.cve_id == "CVE-2024-99001"
    assert r.cvss_score == 9.8
    assert r.cvss_severity == "CRITICAL"
    assert r.description == "Remote code execution in Apache"


def test_get_cve_case_insensitive(db):
    upsert_cve(db, _cve())
    assert get_cve(db, "cve-2024-99001") is not None


def test_upsert_updates_existing(db):
    upsert_cve(db, _cve(epss_score=None))
    upsert_cve(db, _cve(epss_score=0.97, epss_percentile=0.999))
    r = get_cve(db, "CVE-2024-99001")
    assert r.epss_score == pytest.approx(0.97)


def test_epss_enrichment_updates_existing_record(db):
    upsert_cve(db, _cve(epss_score=None, epss_percentile=None))
    upsert_cve(db, CVERecord(cve_id="CVE-2024-99001", epss_score=0.87654, epss_percentile=0.99123))
    r = get_cve(db, "CVE-2024-99001")
    assert r.epss_score == pytest.approx(0.87654, rel=1e-4)
    assert r.cvss_score == 9.8  # original data preserved


def test_kev_enrichment_marks_cve_as_exploited(db):
    upsert_cve(db, _cve(kev=False))
    upsert_cve(
        db,
        CVERecord(
            cve_id="CVE-2024-99001",
            kev=True,
            kev_due_date="2024-04-05",
            kev_required_action="Apply patch immediately.",
        ),
    )
    r = get_cve(db, "CVE-2024-99001")
    assert r.kev is True
    assert r.kev_due_date == "2024-04-05"
    assert r.cvss_score == 9.8  # original data preserved


def test_kev_flag_never_reverts_to_false(db):
    upsert_cve(db, _cve(kev=True))
    upsert_cve(db, CVERecord(cve_id="CVE-2024-99001", kev=False))
    r = get_cve(db, "CVE-2024-99001")
    assert r.kev is True


def test_get_all_cve_ids(db):
    upsert_cve(db, _cve(cve_id="CVE-2024-99001"))
    upsert_cve(db, _cve(cve_id="CVE-2024-99002"))
    assert set(get_all_cve_ids(db)) == {"CVE-2024-99001", "CVE-2024-99002"}


def test_references_stored_and_retrieved(db):
    refs = ["https://example.com/advisory/1", "https://example.com/advisory/2"]
    upsert_cve(db, _cve(references=refs))
    r = get_cve(db, "CVE-2024-99001")
    assert r.references == refs


def test_sync_state_recorded(db):
    update_sync_state(db, "nvd", 1234)
    state = get_sync_state(db, "nvd")
    assert state["source"] == "nvd"
    assert state["records_synced"] == 1234
    assert state["last_sync"] is not None


def test_sync_state_upserts(db):
    update_sync_state(db, "nvd", 100)
    update_sync_state(db, "nvd", 200)
    state = get_sync_state(db, "nvd")
    assert state["records_synced"] == 200


def test_missing_cve_returns_none(db):
    assert get_cve(db, "CVE-9999-00000") is None
