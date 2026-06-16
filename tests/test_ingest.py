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


# WN-003 / WN-004 — NVD date window tests


from wikiness.ingest.nvd import _nvd_date_windows  # noqa: E402


def test_nvd_date_windows_single_window():
    windows = _nvd_date_windows("2026-05-01T00:00:00.000", "2026-06-08T00:00:00.000")
    assert len(windows) == 1
    assert windows[0][0] == "2026-05-01T00:00:00.000"
    assert windows[0][1] == "2026-06-08T00:00:00.000"


def test_nvd_date_windows_splits_at_120_days():
    # 2025-01-01 to 2025-09-01 = 243 days → 3 windows
    windows = _nvd_date_windows("2025-01-01T00:00:00.000", "2025-09-01T00:00:00.000")
    assert len(windows) == 3
    for i in range(len(windows) - 1):
        assert windows[i][1] == windows[i + 1][0]


def test_nvd_date_windows_exact_120_days():
    # 2026-01-01 to 2026-05-01 = exactly 120 days → 1 window (no split)
    windows = _nvd_date_windows("2026-01-01T00:00:00.000", "2026-05-01T00:00:00.000")
    assert len(windows) == 1


def test_iter_nvd_pages_auto_sets_end_date(monkeypatch):
    """When pub_start_date is given without pub_end_date, pubEndDate is auto-set."""
    from wikiness.ingest.nvd import iter_nvd_pages

    captured_params: list[dict] = []

    class FakeResponse:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict:
            return {"totalResults": 0, "vulnerabilities": []}

    class FakeClient:
        def __enter__(self) -> "FakeClient":
            return self

        def __exit__(self, *a: object) -> None:
            pass

        def get(self, url: str, params: dict, headers: dict) -> FakeResponse:
            captured_params.append(dict(params))
            return FakeResponse()

    monkeypatch.setattr("wikiness.ingest.nvd.httpx.Client", lambda **kw: FakeClient())

    list(iter_nvd_pages(pub_start_date="2026-06-01T00:00:00.000"))

    assert captured_params, "at least one NVD request must be made"
    assert "pubEndDate" in captured_params[0], "pubEndDate must be auto-set"
    assert "pubStartDate" in captured_params[0]


# WN-004 — --since-modified tests


def _make_fake_client(captured_params: list[dict]) -> type:
    class FakeResponse:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict:
            return {"totalResults": 0, "vulnerabilities": []}

    class FakeClient:
        def __enter__(self) -> "FakeClient":
            return self

        def __exit__(self, *a: object) -> None:
            pass

        def get(self, url: str, params: dict, headers: dict) -> FakeResponse:
            captured_params.append(dict(params))
            return FakeResponse()

    return FakeClient


def test_iter_nvd_pages_auto_sets_last_mod_end_date(monkeypatch):
    """last_mod_start_date without last_mod_end_date → lastModEndDate auto-set."""
    from wikiness.ingest.nvd import iter_nvd_pages

    captured: list[dict] = []
    monkeypatch.setattr("wikiness.ingest.nvd.httpx.Client", lambda **kw: _make_fake_client(captured)())
    list(iter_nvd_pages(last_mod_start_date="2026-06-01T00:00:00.000"))

    assert captured, "at least one request must be made"
    assert "lastModEndDate" in captured[0], "lastModEndDate must be auto-set"
    assert "lastModStartDate" in captured[0]


def test_iter_nvd_pages_last_mod_uses_correct_param_names(monkeypatch):
    """lastModStartDate / lastModEndDate must use correct NVD API param names (not pubStartDate)."""
    from wikiness.ingest.nvd import iter_nvd_pages

    captured: list[dict] = []
    monkeypatch.setattr("wikiness.ingest.nvd.httpx.Client", lambda **kw: _make_fake_client(captured)())
    list(iter_nvd_pages(
        last_mod_start_date="2026-06-01T00:00:00.000",
        last_mod_end_date="2026-06-08T00:00:00.000",
    ))

    assert "lastModStartDate" in captured[0]
    assert "lastModEndDate" in captured[0]
    assert "pubStartDate" not in captured[0]
    assert "pubEndDate" not in captured[0]


def test_iter_nvd_pages_pub_and_mod_mutually_exclusive():
    """Passing both pub_start_date and last_mod_start_date raises ValueError."""
    import pytest
    from wikiness.ingest.nvd import iter_nvd_pages

    with pytest.raises(ValueError, match="mutually exclusive"):
        list(iter_nvd_pages(
            pub_start_date="2026-06-01T00:00:00.000",
            last_mod_start_date="2026-06-01T00:00:00.000",
        ))


def test_nvd_date_windows_reusable_for_mod_dates():
    """_nvd_date_windows splits mod-date ranges with the same 120-day logic."""
    windows = _nvd_date_windows("2025-01-01T00:00:00.000", "2025-09-01T00:00:00.000")
    assert len(windows) == 3
    for i in range(len(windows) - 1):
        assert windows[i][1] == windows[i + 1][0]


# PoC-in-GitHub tests

from wikiness.ingest.poc import _year_from_cve, fetch_poc, parse_poc_response  # noqa: E402


@pytest.fixture
def poc_data():
    return json.loads((FIXTURES / "poc_found.json").read_text())


def test_year_from_cve_2024():
    assert _year_from_cve("CVE-2024-1234") == "2024"


def test_year_from_cve_log4shell():
    assert _year_from_cve("CVE-2021-44228") == "2021"


def test_parse_poc_found(poc_data):
    result = parse_poc_response(poc_data)
    assert result["public_exploit_available"] is True
    assert result["poc_count"] == 2


def test_parse_poc_not_found():
    result = parse_poc_response([])
    assert result["public_exploit_available"] is False
    assert result["poc_count"] == 0


def test_fetch_poc_url_contains_year_and_cve():
    captured: list[str] = []

    class FakeResp:
        status_code = 404

        def raise_for_status(self) -> None:
            pass

    class FakeClient:
        def get(self, url: str) -> FakeResp:
            captured.append(url)
            return FakeResp()

    fetch_poc("CVE-2024-1234", FakeClient())
    assert len(captured) == 1
    assert "2024" in captured[0]
    assert "CVE-2024-1234" in captured[0]
    assert "raw.githubusercontent.com" in captured[0]


def test_fetch_poc_404_returns_no_exploit():
    class FakeResp:
        status_code = 404

        def raise_for_status(self) -> None:
            pass

    class FakeClient:
        def get(self, url: str) -> FakeResp:
            return FakeResp()

    result = fetch_poc("CVE-2024-99999", FakeClient())
    assert result["public_exploit_available"] is False
    assert result["poc_count"] == 0


def test_fetch_poc_200_returns_exploit(poc_data):
    class FakeResp:
        status_code = 200

        def raise_for_status(self) -> None:
            pass

        def json(self) -> list:
            return poc_data

    class FakeClient:
        def get(self, url: str) -> FakeResp:
            return FakeResp()

    result = fetch_poc("CVE-2024-99001", FakeClient())
    assert result["public_exploit_available"] is True
    assert result["poc_count"] == 2


def test_parse_poc_no_network(monkeypatch):
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("no network")))
    result = parse_poc_response([{"html_url": "https://github.com/example/repo"}])
    assert result["public_exploit_available"] is True
    assert result["poc_count"] == 1
