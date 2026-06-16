from __future__ import annotations

import httpx

POC_BASE_URL = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master"


def _year_from_cve(cve_id: str) -> str:
    return cve_id.split("-")[1]


def parse_poc_response(data: list) -> dict:
    """Return {public_exploit_available, poc_count} from a nomi-sec JSON array."""
    count = len(data) if isinstance(data, list) else 0
    return {"public_exploit_available": count > 0, "poc_count": count}


def fetch_poc(cve_id: str, client: httpx.Client) -> dict:
    """Fetch PoC availability for one CVE. 404 = no PoC known (not an error)."""
    year = _year_from_cve(cve_id)
    url = f"{POC_BASE_URL}/{year}/{cve_id.upper()}.json"
    resp = client.get(url)
    if resp.status_code == 404:
        return parse_poc_response([])
    resp.raise_for_status()
    return parse_poc_response(resp.json())


def enrich_with_poc(cve_ids: list[str]) -> dict[str, dict]:
    """Return {cve_id: {public_exploit_available, poc_count}} for each CVE."""
    result: dict[str, dict] = {}
    with httpx.Client(timeout=30) as client:
        for cve_id in cve_ids:
            result[cve_id] = fetch_poc(cve_id, client)
    return result
