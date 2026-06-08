from __future__ import annotations

import time
from typing import Iterator, Optional

import httpx

from wikiness.config import NVD_BASE_URL, NVD_RESULTS_PER_PAGE
from wikiness.models import CVERecord


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


def iter_nvd_pages(
    api_key: Optional[str] = None,
    pub_start_date: Optional[str] = None,
    pub_end_date: Optional[str] = None,
) -> Iterator[list[CVERecord]]:
    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key

    start_index = 0
    total: Optional[int] = None

    with httpx.Client(timeout=60) as client:
        while total is None or start_index < total:
            params: dict = {
                "startIndex": start_index,
                "resultsPerPage": NVD_RESULTS_PER_PAGE,
            }
            if pub_start_date:
                params["pubStartDate"] = pub_start_date
            if pub_end_date:
                params["pubEndDate"] = pub_end_date

            resp = client.get(NVD_BASE_URL, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()

            total = data["totalResults"]
            vulns = data.get("vulnerabilities", [])

            if not vulns:
                break

            yield [parse_nvd_cve(v) for v in vulns]

            start_index += len(vulns)
            if start_index < total:
                # NVD rate limit: 5 req/30s without key, 50/30s with key
                time.sleep(6.0 if not api_key else 0.6)
