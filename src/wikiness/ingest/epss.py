from __future__ import annotations

import httpx

from wikiness.config import EPSS_API_URL, EPSS_BATCH_SIZE


def fetch_epss_scores(cve_ids: list[str]) -> dict[str, tuple[float, float]]:
    """Return {cve_id: (epss_score, epss_percentile)} for the given CVE IDs."""
    result: dict[str, tuple[float, float]] = {}

    with httpx.Client(timeout=60) as client:
        for i in range(0, len(cve_ids), EPSS_BATCH_SIZE):
            batch = cve_ids[i : i + EPSS_BATCH_SIZE]
            params = {"cve": ",".join(batch), "limit": EPSS_BATCH_SIZE}
            resp = client.get(EPSS_API_URL, params=params)
            resp.raise_for_status()
            result.update(parse_epss_response(resp.json()))

    return result


def parse_epss_response(data: dict) -> dict[str, tuple[float, float]]:
    result: dict[str, tuple[float, float]] = {}
    for item in data.get("data", []):
        cid = item.get("cve")
        if not cid:
            continue
        try:
            epss = float(item["epss"])
            pct = float(item["percentile"])
            result[cid] = (epss, pct)
        except (KeyError, TypeError, ValueError):
            pass
    return result
