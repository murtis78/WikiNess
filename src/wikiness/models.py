from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CVERecord:
    cve_id: str
    title: str = ""
    description: str = ""
    published_date: Optional[str] = None
    last_modified_date: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    cvss_vector: Optional[str] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    kev: bool = False
    kev_due_date: Optional[str] = None
    kev_known_ransomware_campaign_use: Optional[str] = None
    kev_required_action: Optional[str] = None
    public_exploit_available: bool = False
    poc_count: int = 0
    references: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
