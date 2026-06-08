# WikiNess

**Local-first CVE intelligence engine.**

WikiNess is defensive. WikiNess does not execute exploits.  
WikiNess is local-first. WikiNess search works offline after sync.  
WikiNess MVP-001 supports NVD + EPSS + CISA KEV.

---

## What it does

Type a CVE ID or keyword, get a unified, prioritized CVE record with CVSS, EPSS, and CISA KEV context — served entirely from a local SQLite database after a one-time sync.

```
wikiness search apache
wikiness show CVE-2024-12345
wikiness prioritize --kev-only
```

No live queries to third-party services during search. No exploit storage. No exploit execution.

---

## Install

```bash
pip install -e .
```

Requires Python 3.11+.

---

## Usage

### Sync data from official sources

```bash
# Sync all sources (NVD + EPSS + CISA KEV)
wikiness sync all

# Sync individually
wikiness sync nvd
wikiness sync epss
wikiness sync kev

# Sync NVD from a specific date
wikiness sync nvd --since 2024-01-01

# Use NVD API key for higher rate limits
NVD_API_KEY=your-key wikiness sync nvd
```

### Search (offline after sync)

```bash
# Keyword search
wikiness search apache
wikiness search "log4j remote"

# CVE ID lookup
wikiness search CVE-2024-12345

# Filter options
wikiness search openssl --kev-only
wikiness search nginx --min-epss 0.5
wikiness search apache --limit 50
```

### Show a single CVE

```bash
wikiness show CVE-2024-12345
wikiness --json show CVE-2024-12345
```

### Prioritize

```bash
# Top CVEs by priority score
wikiness prioritize

# KEV-only, highest priority first
wikiness prioritize --kev-only

# CVEs with EPSS score above threshold
wikiness prioritize --min-epss 0.3

# JSON output
wikiness --json prioritize --kev-only
```

### Stats

```bash
wikiness stats
wikiness --json stats
```

---

## Priority score

The priority score is transparent and shows all components:

```
priority = cvss_score
         + 3.0  if CISA KEV (actively exploited)
         + epss_score * 2.0
         + 1.0  if CRITICAL severity
```

Example output for `wikiness show CVE-2024-12345`:

```
CVE-2024-12345
  CVSS Score:    9.8
  Severity:      CRITICAL
  EPSS Score:    0.9734
  CISA KEV:      YES — known exploited
  Due Date:      2024-04-05
  Action:        Apply updates per vendor instructions.

  Priority Score: 16.7468
  Reason:         CVSS 9.8, CISA KEV +3.0, EPSS 0.9734 +1.9468, CRITICAL severity +1.0
```

---

## Global options

```bash
wikiness --db /path/to/custom.db search apache
wikiness --json prioritize
```

---

## Data sources

| Source     | Provider | License        |
|------------|----------|----------------|
| NVD        | NIST     | Public domain  |
| EPSS       | FIRST    | CC BY 4.0      |
| CISA KEV   | CISA     | Public domain  |

See [docs/sources.md](docs/sources.md) for details.

---

## Safety

WikiNess is a defensive tool. It will never execute, compile, or store exploit code. See [docs/safety.md](docs/safety.md).

---

## Development

```bash
pip install -e ".[dev]"
pytest
```

---

## Architecture

```
src/wikiness/
  cli.py          Typer CLI — search, show, prioritize, stats, sync
  config.py       URLs and defaults
  models.py       CVERecord dataclass
  storage.py      SQLite + FTS5 — schema, upsert, get, search
  scoring.py      Transparent priority score
  search.py       FTS search and prioritized listing
  ingest/
    nvd.py        NVD CVE API 2.0 ingest
    epss.py       FIRST EPSS API ingest
    kev.py        CISA KEV JSON ingest
```

Database tables: `cve`, `cve_fts` (FTS5), `sync_state`.

---

Under MCPionce governance.
