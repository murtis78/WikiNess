from __future__ import annotations

import time
from datetime import datetime, timedelta
from typing import Iterator, Optional

import httpx

from wikiness.config import NVD_BASE_URL, NVD_RESULTS_PER_PAGE
from wikiness.models import CVERecord

_NVD_DATE_FMT = "%Y-%m-%dT%H:%M:%S.%f"
_NVD_MAX_RANGE_DAYS = 120


def parse_nvd_cve(vuln: dict) -> CVERecord:
    cve = vuln["cve"]
    cve_id: str = cve["id"]

    description = ""
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    cvss_vector: Optional[str] = None

    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            data = m.get("cvssData", {})
            cvss_score = data.get("baseScore")
            cvss_severity = data.get("baseSeverity") or m.get("baseSeverity")
            cvss_vector = data.get("vectorString")
            break

    references = [r["url"] for r in cve.get("references", []) if "url" in r]

    return CVERecord(
        cve_id=cve_id,
        title=cve_id,
        description=description,
        published_date=cve.get("published"),
        last_modified_date=cve.get("lastModified"),
        cvss_score=cvss_score,
        cvss_severity=cvss_severity,
        cvss_vector=cvss_vector,
        references=references,
        sources=["NVD"],
    )


def _nvd_date_windows(start: str, end: str) -> list[tuple[str, str]]:
    """Split [start, end] into ≤120-day windows for NVD API compliance."""
    dt_start = datetime.strptime(start, _NVD_DATE_FMT)
    dt_end = datetime.strptime(end, _NVD_DATE_FMT)
    windows: list[tuple[str, str]] = []
    cursor = dt_start
    while cursor < dt_end:
        win_end = min(cursor + timedelta(days=_NVD_MAX_RANGE_DAYS), dt_end)
        windows.append((
            cursor.strftime(_NVD_DATE_FMT)[:-3],
            win_end.strftime(_NVD_DATE_FMT)[:-3],
        ))
        cursor = win_end
    return windows


def _get_with_retry(
    client: httpx.Client,
    url: str,
    params: dict,
    headers: dict,
    max_retries: int = 3,
) -> httpx.Response:
    """GET with exponential backoff on 5xx or transport errors."""
    for attempt in range(max_retries):
        try:
            resp = client.get(url, params=params, headers=headers)
            resp.raise_for_status()
            return resp
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code < 500 or attempt == max_retries - 1:
                raise
            time.sleep(5.0 * (2 ** attempt))
        except httpx.TransportError:
            if attempt == max_retries - 1:
                raise
            time.sleep(5.0 * (2 ** attempt))
    raise RuntimeError("unreachable")


def _iter_window(
    client: httpx.Client,
    headers: dict,
    api_key: Optional[str],
    pub_start_date: Optional[str],
    pub_end_date: Optional[str],
    last_mod_start_date: Optional[str] = None,
    last_mod_end_date: Optional[str] = None,
) -> Iterator[list[CVERecord]]:
    start_index = 0
    total: Optional[int] = None

    while total is None or start_index < total:
        params: dict = {
            "startIndex": start_index,
            "resultsPerPage": NVD_RESULTS_PER_PAGE,
        }
        if pub_start_date:
            params["pubStartDate"] = pub_start_date
        if pub_end_date:
            params["pubEndDate"] = pub_end_date
        if last_mod_start_date:
            params["lastModStartDate"] = last_mod_start_date
        if last_mod_end_date:
            params["lastModEndDate"] = last_mod_end_date

        resp = _get_with_retry(client, NVD_BASE_URL, params, headers)
        data = resp.json()

        total = data["totalResults"]
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break

        yield [parse_nvd_cve(v) for v in vulns]

        start_index += len(vulns)
        if start_index < total:
            time.sleep(6.0 if not api_key else 0.6)


def iter_nvd_pages(
    api_key: Optional[str] = None,
    pub_start_date: Optional[str] = None,
    pub_end_date: Optional[str] = None,
    last_mod_start_date: Optional[str] = None,
    last_mod_end_date: Optional[str] = None,
) -> Iterator[list[CVERecord]]:
    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key

    if pub_start_date and last_mod_start_date:
        raise ValueError("pub_start_date and last_mod_start_date are mutually exclusive")

    if pub_start_date and not pub_end_date:
        pub_end_date = datetime.utcnow().strftime(_NVD_DATE_FMT)[:-3]
    if last_mod_start_date and not last_mod_end_date:
        last_mod_end_date = datetime.utcnow().strftime(_NVD_DATE_FMT)[:-3]

    if pub_start_date and pub_end_date:
        raw_windows = _nvd_date_windows(pub_start_date, pub_end_date)
        win4: list[tuple[Optional[str], Optional[str], Optional[str], Optional[str]]] = [
            (ws, we, None, None) for ws, we in raw_windows
        ]
    elif last_mod_start_date and last_mod_end_date:
        raw_windows = _nvd_date_windows(last_mod_start_date, last_mod_end_date)
        win4 = [(None, None, ws, we) for ws, we in raw_windows]
    else:
        win4 = [(None, None, None, None)]

    with httpx.Client(timeout=60) as client:
        for p_start, p_end, m_start, m_end in win4:
            yield from _iter_window(client, headers, api_key, p_start, p_end, m_start, m_end)
