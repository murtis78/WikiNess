from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from wikiness.config import DEFAULT_DB_PATH
from wikiness.models import CVERecord
from wikiness.scoring import compute_priority
from wikiness.search import fts_search, prioritized_list
from wikiness.storage import (
    count_cves,
    get_all_cve_ids,
    get_cve,
    get_sync_state,
    init_schema,
    open_db,
    update_sync_state,
    upsert_cve,
)

app = typer.Typer(help="WikiNess — local-first CVE intelligence engine.")
sync_app = typer.Typer(help="Sync CVE data from public sources.")
app.add_typer(sync_app, name="sync")

console = Console()
err_console = Console(stderr=True)


@dataclass
class _State:
    db_path: Path
    json_output: bool


_state = _State(db_path=DEFAULT_DB_PATH, json_output=False)


@app.callback()
def _global(
    db: Optional[Path] = typer.Option(None, "--db", help="Path to SQLite database."),
    json_out: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    global _state
    _state = _State(
        db_path=db if db is not None else DEFAULT_DB_PATH,
        json_output=json_out,
    )


# ---------------------------------------------------------------------------
# sync commands
# ---------------------------------------------------------------------------


@sync_app.command("nvd")
def sync_nvd(
    api_key: Optional[str] = typer.Option(None, envvar="NVD_API_KEY", help="NVD API key."),
    since: Optional[str] = typer.Option(None, help="ISO date to sync from (YYYY-MM-DD)."),
) -> None:
    """Sync CVE records from NVD (requires network)."""
    from wikiness.ingest.nvd import iter_nvd_pages

    conn = open_db(_state.db_path)
    init_schema(conn)

    total = 0
    pub_start = f"{since}T00:00:00.000" if since else None

    with console.status("Syncing NVD…"):
        for page in iter_nvd_pages(api_key=api_key, pub_start_date=pub_start):
            for record in page:
                upsert_cve(conn, record)
                total += 1

    update_sync_state(conn, "nvd", total)
    console.print(f"[green]NVD sync complete:[/green] {total} records.")


@sync_app.command("epss")
def sync_epss() -> None:
    """Enrich existing CVEs with EPSS scores from FIRST (requires network)."""
    from wikiness.ingest.epss import fetch_epss_scores

    conn = open_db(_state.db_path)
    init_schema(conn)

    cve_ids = get_all_cve_ids(conn)
    if not cve_ids:
        console.print("[yellow]No CVEs in database. Run 'wikiness sync nvd' first.[/yellow]")
        raise typer.Exit(1)

    with console.status(f"Fetching EPSS scores for {len(cve_ids)} CVEs…"):
        scores = fetch_epss_scores(cve_ids)
        for cve_id, (epss, pct) in scores.items():
            conn.execute(
                "UPDATE cve SET epss_score = ?, epss_percentile = ?, updated_at = datetime('now') WHERE cve_id = ?",
                (epss, pct, cve_id),
            )
        conn.commit()

    update_sync_state(conn, "epss", len(scores))
    console.print(f"[green]EPSS sync complete:[/green] {len(scores)} records updated.")


@sync_app.command("kev")
def sync_kev() -> None:
    """Mark CVEs from CISA KEV catalog (requires network)."""
    from wikiness.ingest.kev import fetch_kev_catalog, parse_kev_entry

    conn = open_db(_state.db_path)
    init_schema(conn)

    total = 0
    with console.status("Fetching CISA KEV catalog…"):
        entries = fetch_kev_catalog()
        for entry in entries:
            upsert_cve(conn, parse_kev_entry(entry))
            total += 1

    update_sync_state(conn, "kev", total)
    console.print(f"[green]KEV sync complete:[/green] {total} records.")


@sync_app.command("all")
def sync_all(
    api_key: Optional[str] = typer.Option(None, envvar="NVD_API_KEY"),
    since: Optional[str] = typer.Option(None, help="ISO date to sync from (YYYY-MM-DD)."),
) -> None:
    """Sync all sources: NVD, EPSS, CISA KEV."""
    sync_nvd(api_key=api_key, since=since)
    sync_epss()
    sync_kev()


# ---------------------------------------------------------------------------
# query commands (offline after sync)
# ---------------------------------------------------------------------------


@app.command()
def search(
    query: str = typer.Argument(..., help="Search query (keyword or CVE ID)."),
    limit: int = typer.Option(20, "--limit", help="Maximum results."),
    kev_only: bool = typer.Option(False, "--kev-only", help="Only CISA KEV entries."),
    min_epss: Optional[float] = typer.Option(None, "--min-epss", help="Minimum EPSS score."),
) -> None:
    """Search CVEs in local database (offline after sync)."""
    conn = open_db(_state.db_path)
    init_schema(conn)

    try:
        results = fts_search(conn, query, limit=limit, kev_only=kev_only, min_epss=min_epss)
    except Exception as exc:
        err_console.print(f"[red]Search error:[/red] {exc}")
        raise typer.Exit(1)

    if not results:
        if _state.json_output:
            print(json.dumps([]))
        else:
            console.print("[yellow]No results found.[/yellow]")
        return

    if _state.json_output:
        print(json.dumps([_record_to_dict(r) for r in results], indent=2))
        return

    table = Table(title=f"Search: {query}", show_lines=False)
    table.add_column("CVE ID", style="cyan", no_wrap=True)
    table.add_column("CVSS", justify="right")
    table.add_column("EPSS", justify="right")
    table.add_column("KEV", justify="center")
    table.add_column("Severity")
    table.add_column("Description", max_width=70)

    for r in results:
        snippet = r.description[:100] + "…" if len(r.description) > 100 else r.description
        table.add_row(
            r.cve_id,
            f"{r.cvss_score:.1f}" if r.cvss_score is not None else "—",
            f"{r.epss_score:.4f}" if r.epss_score is not None else "—",
            "[red]YES[/red]" if r.kev else "no",
            r.cvss_severity or "—",
            snippet,
        )
    console.print(table)


@app.command()
def show(
    cve_id: str = typer.Argument(..., help="CVE ID to display."),
) -> None:
    """Show full canonical record for a CVE (offline after sync)."""
    conn = open_db(_state.db_path)
    init_schema(conn)

    record = get_cve(conn, cve_id.upper())
    if record is None:
        console.print(f"[yellow]CVE {cve_id} not found in local database.[/yellow]")
        raise typer.Exit(1)

    score = compute_priority(record)

    if _state.json_output:
        out = _record_to_dict(record)
        out["priority"] = {
            "final_score": score.final_score,
            "base_cvss": score.base_cvss,
            "kev_boost": score.kev_boost,
            "epss_boost": score.epss_boost,
            "severity_boost": score.severity_boost,
            "reason": score.reason,
        }
        print(json.dumps(out, indent=2))
        return

    console.print(f"\n[bold cyan]{record.cve_id}[/bold cyan]")
    console.print(f"  [bold]Description:[/bold]  {record.description}")
    console.print(f"  [bold]Published:[/bold]    {record.published_date or '—'}")
    console.print(f"  [bold]Modified:[/bold]     {record.last_modified_date or '—'}")
    console.print(f"\n  [bold]CVSS Score:[/bold]   {record.cvss_score if record.cvss_score is not None else '—'}")
    console.print(f"  [bold]Severity:[/bold]     {record.cvss_severity or '—'}")
    console.print(f"  [bold]Vector:[/bold]       {record.cvss_vector or '—'}")
    console.print(f"\n  [bold]EPSS Score:[/bold]   {record.epss_score if record.epss_score is not None else '—'}")
    console.print(f"  [bold]EPSS Pctile:[/bold]  {record.epss_percentile if record.epss_percentile is not None else '—'}")
    console.print(f"\n  [bold]CISA KEV:[/bold]     {'[red]YES — known exploited[/red]' if record.kev else 'no'}")
    if record.kev:
        console.print(f"  [bold]Due Date:[/bold]     {record.kev_due_date or '—'}")
        console.print(f"  [bold]Ransomware:[/bold]   {record.kev_known_ransomware_campaign_use or '—'}")
        console.print(f"  [bold]Action:[/bold]       {record.kev_required_action or '—'}")
    console.print(f"\n  [bold]Priority Score:[/bold] {score.final_score}")
    console.print(f"  [bold]Reason:[/bold]         {score.reason}")
    if record.references:
        console.print(f"\n  [bold]References:[/bold]")
        for ref in record.references[:5]:
            console.print(f"    {ref}")


@app.command()
def prioritize(
    limit: int = typer.Option(20, "--limit", help="Maximum results."),
    kev_only: bool = typer.Option(False, "--kev-only", help="Only CISA KEV entries."),
    min_epss: Optional[float] = typer.Option(None, "--min-epss", help="Minimum EPSS score."),
) -> None:
    """List CVEs ordered by transparent priority score (offline after sync)."""
    conn = open_db(_state.db_path)
    init_schema(conn)

    results = prioritized_list(conn, limit=limit, kev_only=kev_only, min_epss=min_epss)

    if not results:
        console.print("[yellow]No CVEs found matching criteria.[/yellow]")
        return

    if _state.json_output:
        out = []
        for record, score in results:
            d = _record_to_dict(record)
            d["priority"] = {"final_score": score.final_score, "reason": score.reason}
            out.append(d)
        print(json.dumps(out, indent=2))
        return

    table = Table(title="CVE Priority List", show_lines=False)
    table.add_column("Score", justify="right", style="bold yellow")
    table.add_column("CVE ID", style="cyan", no_wrap=True)
    table.add_column("CVSS", justify="right")
    table.add_column("EPSS", justify="right")
    table.add_column("KEV", justify="center")
    table.add_column("Reason")

    for record, score in results:
        table.add_row(
            f"{score.final_score:.2f}",
            record.cve_id,
            f"{record.cvss_score:.1f}" if record.cvss_score is not None else "—",
            f"{record.epss_score:.4f}" if record.epss_score is not None else "—",
            "[red]YES[/red]" if record.kev else "no",
            score.reason,
        )
    console.print(table)


@app.command()
def stats() -> None:
    """Show database statistics."""
    conn = open_db(_state.db_path)
    init_schema(conn)

    total = count_cves(conn)
    kev_count = conn.execute("SELECT COUNT(*) FROM cve WHERE kev = 1").fetchone()[0]
    critical_count = conn.execute("SELECT COUNT(*) FROM cve WHERE cvss_severity = 'CRITICAL'").fetchone()[0]
    with_epss = conn.execute("SELECT COUNT(*) FROM cve WHERE epss_score IS NOT NULL").fetchone()[0]

    sync_sources = {src: get_sync_state(conn, src) for src in ("nvd", "epss", "kev")}

    if _state.json_output:
        print(
            json.dumps(
                {
                    "total_cves": total,
                    "kev_count": kev_count,
                    "critical_count": critical_count,
                    "with_epss_score": with_epss,
                    "sync_state": sync_sources,
                },
                indent=2,
            )
        )
        return

    console.print(f"\n[bold]WikiNess Database Stats[/bold]  ({_state.db_path})")
    console.print(f"  Total CVEs:     {total}")
    console.print(f"  CISA KEV:       {kev_count}")
    console.print(f"  Critical CVSS:  {critical_count}")
    console.print(f"  With EPSS:      {with_epss}")
    console.print("\n[bold]Sync State:[/bold]")
    for src, state in sync_sources.items():
        if state:
            console.print(f"  {src:10s}  last={state['last_sync']}  records={state['records_synced']}")
        else:
            console.print(f"  {src:10s}  never synced")


def _record_to_dict(r: CVERecord) -> dict:
    return {
        "cve_id": r.cve_id,
        "title": r.title,
        "description": r.description,
        "published_date": r.published_date,
        "last_modified_date": r.last_modified_date,
        "cvss_score": r.cvss_score,
        "cvss_severity": r.cvss_severity,
        "cvss_vector": r.cvss_vector,
        "epss_score": r.epss_score,
        "epss_percentile": r.epss_percentile,
        "kev": r.kev,
        "kev_due_date": r.kev_due_date,
        "kev_known_ransomware_campaign_use": r.kev_known_ransomware_campaign_use,
        "kev_required_action": r.kev_required_action,
        "references": r.references,
        "sources": r.sources,
    }


if __name__ == "__main__":
    app()
