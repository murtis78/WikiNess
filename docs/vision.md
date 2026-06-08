# WikiNess Vision

WikiNess is a local-first CVE intelligence engine built for defensive security operations.

## Core promise

Type a CVE ID or keyword, get a local, unified, prioritized CVE record with CVSS, EPSS and CISA KEV context — without sending live search queries to third-party services.

## Design principles

**Local-first.** After a sync, all search, show, and prioritize operations run entirely against a local SQLite database. No network required.

**Transparent scoring.** The priority score is a simple, explainable formula with visible components (CVSS base, EPSS boost, KEV boost, severity boost). There is no opaque ML model.

**Defensive only.** WikiNess ingests public vulnerability metadata and normalizes it for defensive decision-making — patching prioritization, investigation triage, and risk awareness. It does not store, execute, or assist with exploit code.

**Minimal dependencies.** SQLite FTS5 (stdlib), Typer, httpx, Rich. No search engines, no message queues, no LLM frameworks.

## MVP-001 scope

- NVD CVE API 2.0
- FIRST EPSS API
- CISA KEV catalog
- SQLite with FTS5
- Typer CLI

## Future direction (not in MVP-001)

Future versions may add additional defensive data sources (NVD CPE, CVSS change history, vendor advisories), richer search filters, and a structured export format for SIEM/SOAR integration. Exploit data sources are permanently out of scope.
