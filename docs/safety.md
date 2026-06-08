# WikiNess Safety Policy

WikiNess is a defensive tool. This document states what WikiNess will never do and why.

## Permanent constraints

WikiNess will never:

- Execute exploit code
- Compile exploit code
- Launch proof-of-concept (PoC) exploits
- Store PoC exploit code
- Scan systems or networks
- Attack systems or services
- Provide automation for offensive operations
- Index exploit databases (Exploit-DB, PacketStorm, trickest/cve, PoC-in-GitHub)

These constraints are not temporary. They are part of the product definition.

## What WikiNess does

WikiNess ingests public vulnerability metadata from official sources:

- NVD (National Vulnerability Database)
- FIRST EPSS (Exploit Prediction Scoring System)
- CISA KEV (Known Exploited Vulnerabilities catalog)

It normalizes this metadata into a canonical CVE record, stores it locally, and exposes it for search and prioritization.

The goal is to help defenders answer: "Which CVEs should I patch or investigate first, and why?"

## Data sources policy

WikiNess MVP-001 connects to:

- `https://services.nvd.nist.gov/` — official NIST NVD API
- `https://api.first.org/` — official FIRST EPSS API
- `https://www.cisa.gov/` — official CISA KEV feed

No other external connections are made.

## Governance

WikiNess is developed under MCPionce governance. Security concerns should be reported to the project maintainers.
