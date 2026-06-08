import json
import socket
from pathlib import Path

import pytest

from wikiness.ingest.epss import parse_epss_response
from wikiness.ingest.kev import parse_kev_catalog
from wikiness.ingest.nvd import parse_nvd_cve

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def nvd_data():
    return json.loads((FIXTURES / "nvd_response.json").read_text())


@pytest.fixture
def epss_data():
    return json.loads((FIXTURES / "epss_response.json").read_text())


@pytest.fixture
def kev_data():
    return json.loads((FIXTURES / "kev_catalog.json").read_text())


def test_parse_nvd_cve_id(nvd_data):
    r = parse_nvd_cve(nvd_data["vulnerabilities"][0])
    assert r.cve_id == "CVE-2024-99001"


def test_parse_nvd_cvss_score(nvd_data):
    r = parse_nvd_cve(nvd_data["vulnerabilities"][0])
    assert r.cvss_score == 9.8


def test_parse_nvd_severity(nvd_data):
    r = parse_nvd_cve(nvd_data["vulnerabilities"][0])
    assert r.cvss_severity == "CRITICAL"


def test_parse_nvd_description_english_only(nvd_data):
    r = parse_nvd_cve(nvd_data["vulnerabilities"][0])
    assert "Apache" in r.description
    assert "vulnérabilité" not in r.description  # French description excluded


def test_parse_nvd_source_tag(nvd_data):
    r = parse_nvd_cve(nvd_data["vulnerabilities"][0])
    assert "NVD" in r.sources


def test_parse_nvd_references(nvd_data):
    r = parse_nvd_cve(nvd_data["vulnerabilities"][0])
    assert len(r.references) >= 1
    assert r.references[0].startswith("https://")


def test_parse_nvd_second_cve(nvd_data):
    r = parse_nvd_cve(nvd_data["vulnerabilities"][1])
    assert r.cve_id == "CVE-2024-99002"
    assert r.cvss_score == 6.5
    assert r.cvss_severity == "MEDIUM"


def test_parse_epss_scores(epss_data):
    scores = parse_epss_response(epss_data)
    assert "CVE-2024-99001" in scores
    epss, pct = scores["CVE-2024-99001"]
    assert epss == pytest.approx(0.97345, rel=1e-4)
    assert pct == pytest.approx(0.99987, rel=1e-4)


def test_parse_epss_second_entry(epss_data):
    scores = parse_epss_response(epss_data)
    epss, pct = scores["CVE-2024-99002"]
    assert epss == pytest.approx(0.01234, rel=1e-4)


def test_parse_kev_count(kev_data):
    records = parse_kev_catalog(kev_data)
    assert len(records) == 1


def test_parse_kev_cve_id(kev_data):
    r = parse_kev_catalog(kev_data)[0]
    assert r.cve_id == "CVE-2024-99001"


def test_parse_kev_flags_as_exploited(kev_data):
    r = parse_kev_catalog(kev_data)[0]
    assert r.kev is True


def test_parse_kev_due_date(kev_data):
    r = parse_kev_catalog(kev_data)[0]
    assert r.kev_due_date == "2024-04-05"


def test_parse_kev_ransomware_field(kev_data):
    r = parse_kev_catalog(kev_data)[0]
    assert r.kev_known_ransomware_campaign_use == "Known"


def test_parse_kev_required_action(kev_data):
    r = parse_kev_catalog(kev_data)[0]
    assert "vendor instructions" in r.kev_required_action


def test_parse_kev_source_tag(kev_data):
    r = parse_kev_catalog(kev_data)[0]
    assert "CISA_KEV" in r.sources


def test_ingest_parsers_do_not_use_network(monkeypatch, nvd_data, epss_data, kev_data):
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("no network")))
    records = [parse_nvd_cve(v) for v in nvd_data["vulnerabilities"]]
    assert len(records) == 2
    scores = parse_epss_response(epss_data)
    assert len(scores) == 2
    kev_records = parse_kev_catalog(kev_data)
    assert len(kev_records) == 1
