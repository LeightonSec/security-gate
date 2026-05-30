import sys
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from security_gate import __version__
from security_gate.accepted import load_accepted, partition_findings
from security_gate.scanner import ALL_SCANNERS
from security_gate.scanner.base import Severity
from security_gate.report.generator import generate_json, generate_markdown, gate_passed
from security_gate.sbom import generate_sbom_json

app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console()

_SEVERITY_COLOUR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


class OutputFormat(str, Enum):
    markdown = "markdown"
    json = "json"
    both = "both"


@app.callback()
def _startup() -> None:
    """Static security gate scanner for Python security projects."""


@app.command()
def scan(
    path: Path = typer.Argument(..., help="Path to the repo root to scan"),
    output: OutputFormat = typer.Option(OutputFormat.markdown, "--output", "-o", help="Report format"),
    save: bool = typer.Option(False, "--save", "-s", help="Save report(s) to ./security-gate-report.*"),
    sbom: bool = typer.Option(False, "--sbom", help="Also generate a CycloneDX 1.5 SBOM for the scanned repo"),
    exit_code: bool = typer.Option(True, "--exit-code/--no-exit-code", help="Exit 1 if gate is blocked"),
    exclude: list[str] = typer.Option([], "--exclude", "-e", help="Additional directory names to exclude (repeatable)"),
    url: str | None = typer.Option(None, "--url", help="Base URL of a running service to DAST scan (e.g. http://localhost:5001)"),
) -> None:
    """Scan a repo and produce a security gate report."""
    if not path.is_dir():
        console.print(f"[red]Error:[/red] {path} is not a directory")
        raise typer.Exit(1)

    console.print(f"\n[bold]security-gate[/bold] v{__version__} — scanning [cyan]{path.resolve()}[/cyan]\n")

    extra_excludes = frozenset(exclude)
    all_findings = []
    for scanner_cls in ALL_SCANNERS:
        scanner = scanner_cls(excludes=extra_excludes)
        findings = scanner.scan(path)
        all_findings.extend(findings)
        status = f"[red]{len(findings)} findings[/red]" if findings else "[green]clean[/green]"
        console.print(f"  {scanner.name:<22} {status}")

    if url:
        from security_gate.dast import DastScanner
        try:
            dast = DastScanner(base_url=url)
            dast_findings = dast.scan()
            all_findings.extend(dast_findings)
            dast_status = f"[red]{len(dast_findings)} findings[/red]" if dast_findings else "[green]clean[/green]"
            console.print(f"  {'dast':<22} {dast_status}")
        except ConnectionError as exc:
            console.print(f"  [yellow]{'dast':<22}[/yellow] [yellow]skipped — {exc}[/yellow]")

    console.print()

    # Partition accepted findings — only active findings affect the gate
    accepted_entries = load_accepted(path)
    active_findings, suppressed = partition_findings(all_findings, accepted_entries)

    passed = gate_passed(active_findings)

    # Summary table (active findings only)
    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity")
    table.add_column("Count", justify="right")

    severity_counts = {s: 0 for s in Severity}
    for f in active_findings:
        severity_counts[f.severity] += 1

    for sev in Severity:
        count = severity_counts[sev]
        colour = _SEVERITY_COLOUR[sev]
        table.add_row(f"[{colour}]{sev.value}[/{colour}]", str(count))

    console.print(table)
    console.print()

    if suppressed:
        console.print(f"[dim]{len(suppressed)} finding(s) accepted via accepted-findings.toml[/dim]\n")

    if passed:
        console.print("[bold green]✅ GATE PASSED[/bold green] — no CRITICAL or HIGH findings\n")
    else:
        console.print("[bold red]❌ GATE BLOCKED[/bold red] — resolve CRITICAL/HIGH findings before proceeding\n")

    console.print(
        "[dim]Note: scanners cover single-file scope — cross-function taint, "
        "cross-file configuration, and infrastructure controls require manual verification.[/dim]\n"
    )

    # Active findings
    if active_findings:
        for f in sorted(active_findings, key=lambda x: x.sort_key()):
            colour = _SEVERITY_COLOUR[f.severity]
            if hasattr(f, "file"):
                console.print(
                    f"  [{colour}]{f.severity.value:<8}[/{colour}] "
                    f"[cyan]{f.file}:{f.line}[/cyan]  [dim]{f.scanner}[/dim]"
                )
            else:
                sc = f" · HTTP {f.status_code}" if f.status_code is not None else ""
                console.print(
                    f"  [{colour}]{f.severity.value:<8}[/{colour}] "
                    f"[cyan]{f.endpoint}[/cyan]  [dim]{f.scanner} · {f.payload_variant}{sc}[/dim]"
                )
            console.print(f"           {f.detail}")
            console.print(f"           [dim]→ {f.checklist_item}[/dim]\n")

    # Accepted findings — severity stays visible
    if suppressed:
        console.print("[dim]── accepted findings (excluded from gate) ──[/dim]\n")
        for f, entry in suppressed:
            colour = _SEVERITY_COLOUR[f.severity]
            if hasattr(f, "file"):
                console.print(
                    f"  [dim]ACCEPTED {f.severity.value:<8}[/dim] "
                    f"[dim]{f.file}:{f.line}  {f.scanner}[/dim]"
                )
            else:
                console.print(
                    f"  [dim]ACCEPTED {f.severity.value:<8}[/dim] "
                    f"[dim]{getattr(f, 'endpoint', '')}  {f.scanner}[/dim]"
                )
            console.print(f"           [dim]rationale: {entry.rationale}[/dim]")
            console.print(f"           [dim]reviewer: {entry.reviewer}  {entry.date}[/dim]\n")

    # Save reports
    repo_str = str(path.resolve())
    if output in (OutputFormat.markdown, OutputFormat.both):
        md = generate_markdown(active_findings, repo_str, accepted=suppressed)
        if save:
            out_path = Path("security-gate-report.md")
            out_path.write_text(md, encoding="utf-8")
            console.print(f"[dim]Report saved: {out_path}[/dim]")
        else:
            console.print(md)

    if output in (OutputFormat.json, OutputFormat.both):
        j = generate_json(active_findings, repo_str, accepted=suppressed)
        if save:
            out_path = Path("security-gate-report.json")
            out_path.write_text(j, encoding="utf-8")
            console.print(f"[dim]Report saved: {out_path}[/dim]")
        else:
            console.print(j)

    if sbom:
        sbom_json = generate_sbom_json(path)
        sbom_path = Path("security-gate-sbom.cdx.json")
        sbom_path.write_text(sbom_json, encoding="utf-8")
        console.print(f"[dim]SBOM saved: {sbom_path} (CycloneDX 1.5)[/dim]")

    if exit_code and not passed:
        raise typer.Exit(1)


@app.command()
def version() -> None:
    """Show version and exit."""
    console.print(f"security-gate v{__version__}")


if __name__ == "__main__":
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted.[/dim]")
        sys.exit(0)
