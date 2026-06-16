# WikiNess Data Sources

## NVD — National Vulnerability Database

- **Provider:** NIST (National Institute of Standards and Technology)
- **URL:** https://nvd.nist.gov/
- **API:** https://services.nvd.nist.gov/rest/json/cves/2.0
- **License:** Public domain (U.S. government work)
- **Data:** CVE identifiers, descriptions, CVSS scores, references, publication dates
- **Rate limits:** 5 requests/30s without API key; 50 requests/30s with `NVD_API_KEY`
- **WikiNess command:** `wikiness sync nvd`

## FIRST EPSS — Exploit Prediction Scoring System

- **Provider:** FIRST (Forum of Incident Response and Security Teams)
- **URL:** https://www.first.org/epss/
- **API:** https://api.first.org/data/v1/epss
- **License:** CC BY 4.0
- **Data:** Per-CVE probability of exploitation in the next 30 days, percentile rank
- **WikiNess command:** `wikiness sync epss`
- **Note:** EPSS sync requires CVEs already present in the local database (run `sync nvd` first)

## CISA KEV — Known Exploited Vulnerabilities Catalog

- **Provider:** CISA (Cybersecurity and Infrastructure Security Agency)
- **URL:** https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **Feed:** https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- **License:** Public domain (U.S. government work)
- **Data:** CVEs confirmed to be actively exploited, required remediation actions, due dates, ransomware campaign association
- **WikiNess command:** `wikiness sync kev`
- **Note:** CISA KEV entries that are not yet in the local NVD dataset are inserted as partial records and enriched when NVD is synced

## PoC-in-GitHub — nomi-sec

- **Provider:** nomi-sec (community, open-source, CC0)
- **Repository:** https://github.com/nomi-sec/PoC-in-GitHub
- **Feed:** `https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/<YEAR>/<CVE-ID>.json`
  - `<YEAR>` derived from CVE-ID (e.g. `CVE-2021-44228` → `2021`)
  - HTTP 404 = no PoC known for that CVE (not an error)
- **License:** CC0 1.0 Universal (Public Domain Dedication)
- **Data:** List of public proof-of-concept repositories per CVE; fields used: count of entries
- **Rate limits:** GitHub CDN — no enforced rate limit; 1 GET per CVE at sync time
- **WikiNess command:** `wikiness sync poc`
- **Note:** PoC sync requires CVEs already present in the local database. Enriches existing records only.
- **Auth:** none (keyless, public CDN)

## Priority score formula

```
priority = cvss_score
         + 3.0 if kev == True
         + epss_score * 2.0
         + 1.0 if cvss_severity == CRITICAL
         + 2.0 if public_exploit_available == True
```

All components are visible in `wikiness show` and `wikiness prioritize` output.
