from __future__ import annotations

import httpx

from wikiness.config import KEV_JSON_URL
from wikiness.models import CVERecord


def fetch_kev_catalog() -> list[dict]:
    with httpx.Client(timeout=60) as client:
        resp = client.get(KEV_JSON_URL)
        resp.raise_for_status()
        return resp.json().get("vulnerabilities", [])


def parse_kev_entry(entry: dict) -> CVERecord:
    return CVERecord(
        cve_id=entry.get("cveID", ""),
        title=entry.get("vulnerabilityName", ""),
        kev=True,
        kev_due_date=entry.get("dueDate"),
        kev_known_ransomware_campaign_use=entry.get("knownRansomwareCampaignUse"),
        kev_required_action=entry.get("requiredAction"),
        sources=["CISA_KEV"],
    )


def parse_kev_catalog(data: dict) -> list[CVERecord]:
    return [parse_kev_entry(v) for v in data.get("vulnerabilities", [])]
