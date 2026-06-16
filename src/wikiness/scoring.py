from __future__ import annotations

from dataclasses import dataclass

from wikiness.models import CVERecord


@dataclass
class PriorityScore:
    cve_id: str
    base_cvss: float
    kev_boost: float
    epss_boost: float
    severity_boost: float
    poc_boost: float
    final_score: float
    reason: str


def compute_priority(record: CVERecord) -> PriorityScore:
    base = record.cvss_score or 0.0
    kev_boost = 3.0 if record.kev else 0.0
    epss_boost = round((record.epss_score or 0.0) * 2.0, 4)
    severity_boost = 1.0 if (record.cvss_severity or "").upper() == "CRITICAL" else 0.0
    poc_boost = 2.0 if record.public_exploit_available else 0.0

    final = round(base + kev_boost + epss_boost + severity_boost + poc_boost, 4)

    parts: list[str] = []
    if base > 0:
        parts.append(f"CVSS {base}")
    if kev_boost > 0:
        parts.append(f"CISA KEV +{kev_boost}")
    if epss_boost > 0:
        parts.append(f"EPSS {record.epss_score:.4f} +{epss_boost}")
    if severity_boost > 0:
        parts.append(f"CRITICAL severity +{severity_boost}")
    if poc_boost > 0:
        parts.append(f"PoC public exploit +{poc_boost} ({record.poc_count})")

    return PriorityScore(
        cve_id=record.cve_id,
        base_cvss=base,
        kev_boost=kev_boost,
        epss_boost=epss_boost,
        severity_boost=severity_boost,
        poc_boost=poc_boost,
        final_score=final,
        reason=", ".join(parts) if parts else "no scored data",
    )
