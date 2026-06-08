import pytest

from wikiness.models import CVERecord
from wikiness.scoring import compute_priority


def test_kev_scores_higher_than_non_kev():
    kev = CVERecord(cve_id="CVE-2024-99001", cvss_score=7.5, cvss_severity="HIGH", kev=True, epss_score=0.1)
    non_kev = CVERecord(cve_id="CVE-2024-99002", cvss_score=7.5, cvss_severity="HIGH", kev=False, epss_score=0.1)
    assert compute_priority(kev).final_score > compute_priority(non_kev).final_score


def test_kev_boost_is_3():
    cve = CVERecord(cve_id="CVE-2024-99001", cvss_score=5.0, kev=True)
    assert compute_priority(cve).kev_boost == 3.0


def test_no_kev_boost_is_zero():
    cve = CVERecord(cve_id="CVE-2024-99001", cvss_score=9.8, kev=False)
    assert compute_priority(cve).kev_boost == 0.0


def test_critical_severity_boost_is_1():
    cve = CVERecord(cve_id="CVE-2024-99001", cvss_score=9.8, cvss_severity="CRITICAL")
    assert compute_priority(cve).severity_boost == 1.0


def test_non_critical_severity_no_boost():
    cve = CVERecord(cve_id="CVE-2024-99001", cvss_score=7.0, cvss_severity="HIGH")
    assert compute_priority(cve).severity_boost == 0.0


def test_epss_boost_proportional_to_score():
    cve = CVERecord(cve_id="CVE-2024-99001", epss_score=0.5)
    score = compute_priority(cve)
    assert score.epss_boost == pytest.approx(1.0)


def test_no_data_gives_zero_score():
    cve = CVERecord(cve_id="CVE-2024-99001")
    assert compute_priority(cve).final_score == 0.0


def test_final_score_is_sum_of_components():
    cve = CVERecord(
        cve_id="CVE-2024-99001",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        kev=True,
        epss_score=0.5,
    )
    score = compute_priority(cve)
    expected = 9.8 + 3.0 + (0.5 * 2.0) + 1.0
    assert score.final_score == pytest.approx(expected, rel=1e-4)


def test_reason_shows_cvss():
    cve = CVERecord(cve_id="CVE-2024-99001", cvss_score=9.8)
    assert "CVSS" in compute_priority(cve).reason


def test_reason_shows_kev():
    cve = CVERecord(cve_id="CVE-2024-99001", kev=True)
    assert "CISA KEV" in compute_priority(cve).reason


def test_reason_shows_epss():
    cve = CVERecord(cve_id="CVE-2024-99001", epss_score=0.97)
    assert "EPSS" in compute_priority(cve).reason


def test_reason_shows_all_components():
    cve = CVERecord(
        cve_id="CVE-2024-99001",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        kev=True,
        epss_score=0.97,
    )
    reason = compute_priority(cve).reason
    assert "CVSS" in reason
    assert "CISA KEV" in reason
    assert "EPSS" in reason
    assert "CRITICAL" in reason


def test_no_data_reason_message():
    cve = CVERecord(cve_id="CVE-2024-99001")
    assert "no scored data" in compute_priority(cve).reason
