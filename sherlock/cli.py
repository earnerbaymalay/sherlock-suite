"""
Command-line interface for Sherlock OSINT & Attack Surface Suite.
Provides both CLI headless scanning and interactive Textual TUI launcher.
"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .engine import SherlockEngine
from .models import InvestigationDepth, Severity, Target, ClientProfile, ClientType
from .modules import ALL_MODULES, MODULE_MAP
from .reports import ReportGenerator
from .tui import launch as launch_tui


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sherlock",
        description="Sherlock - Defensive OSINT & Infrastructure Attack Surface Management Suite",
    )
    subparsers = parser.add_subparsers(dest="command")

    # TUI command
    subparsers.add_parser("tui", help="Launch interactive Terminal User Interface (TUI)")

    # Modules list command
    subparsers.add_parser("modules", help="List all available discovery modules")

    # Scan command (CLI headless)
    scan_parser = subparsers.add_parser("scan", help="Run automated non-interactive OSINT scan")
    scan_parser.add_argument("target", help="Target domain (e.g. example.com)")
    scan_parser.add_argument(
        "-d",
        "--depth",
        choices=["quick", "standard", "deep"],
        default="standard",
        help="Investigation depth (default: standard)",
    )
    scan_parser.add_argument(
        "-m",
        "--modules",
        help="Comma-separated module IDs to execute (default: all)",
    )
    scan_parser.add_argument(
        "-o",
        "--output",
        help="Output Markdown report path (e.g. report.md)",
    )
    scan_parser.add_argument(
        "-j",
        "--json",
        help="Output JSON data path (e.g. result.json)",
    )
    scan_parser.add_argument(
        "-H",
        "--html",
        help="Output HTML report path (e.g. report.html)",
    )

    # Verify command (Client / Person / Business Due Diligence)
    verify_parser = subparsers.add_parser(
        "verify", help="Run due diligence audit on a client, vendor, person, or business"
    )
    verify_parser.add_argument(
        "-t",
        "--type",
        choices=["business", "person"],
        default="business",
        help="Target entity type: 'business' or 'person' (default: business)",
    )
    verify_parser.add_argument("-n", "--name", help="Individual name or principal's legal name")
    verify_parser.add_argument("-c", "--company", help="Company / trading entity name")
    verify_parser.add_argument("-e", "--email", help="Contact email address")
    verify_parser.add_argument("-p", "--phone", help="Contact phone number (international format e.g. +61412345678)")
    verify_parser.add_argument("-a", "--address", help="Claimed office or business address")
    verify_parser.add_argument("-D", "--domain", help="Company website / domain")
    verify_parser.add_argument(
        "-d",
        "--depth",
        choices=["quick", "standard", "deep"],
        default="standard",
        help="Investigation depth (default: standard)",
    )
    verify_parser.add_argument(
        "-o",
        "--output",
        help="Output Markdown report path",
    )
    verify_parser.add_argument(
        "-j",
        "--json",
        help="Output JSON data path",
    )
    verify_parser.add_argument(
        "-H",
        "--html",
        help="Output HTML report path",
    )

    return parser.parse_args()


async def run_cli_scan(args: argparse.Namespace) -> int:
    console = Console()
    try:
        depth = InvestigationDepth(args.depth)
        target = Target(domain=args.target, depth=depth)
    except Exception as e:
        console.print(f"[bold red]Target Error:[/] {e}")
        return 1

    # Select modules
    if args.modules:
        selected_ids = [m.strip() for m in args.modules.split(",")]
        for m in selected_ids:
            if m not in MODULE_MAP:
                console.print(f"[bold red]Unknown module ID:[/] {m}")
                return 1
    else:
        selected_ids = list(MODULE_MAP.keys())

    console.print(
        Panel(
            f"[bold cyan]Sherlock OSINT Suite[/bold cyan]\n"
            f"Target: [bold white]{target.domain}[/bold white] | Depth: [yellow]{target.depth.value}[/yellow] | "
            f"Modules: [green]{len(selected_ids)}[/green]",
            title="Investigation Initialized",
            border_style="cyan",
        )
    )

    engine = SherlockEngine.from_module_ids(selected_ids)

    with console.status(f"[bold green]Executing Sherlock modules on {target.domain}...[/bold green]"):
        result = await engine.run(target)

    s = result.summary
    console.print()

    # Summary Panel
    score_style = "green" if s.risk_score < 30 else ("yellow" if s.risk_score < 60 else "red")
    console.print(
        Panel(
            f"[bold]Target Domain:[/] {s.target_domain}\n"
            f"[bold]Duration:[/] {s.duration_seconds}s\n"
            f"[bold]Risk Score:[/] [{score_style}]{s.risk_score} / 100[/{score_style}]\n"
            f"[bold]Subdomains Discovered:[/] {s.subdomains_count}\n"
            f"[bold]Total Findings:[/] {s.total_findings}",
            title="[bold]Audit Summary[/bold]",
            border_style=score_style,
        )
    )

    # Findings Table
    if result.findings:
        table = Table(title="Correlated Security Findings", show_lines=True)
        table.add_column("Severity", justify="center", width=10)
        table.add_column("Category", width=14)
        table.add_column("Finding", style="bold")
        table.add_column("Target Asset", style="dim")
        table.add_column("Source", style="dim")

        for f in result.findings:
            table.add_row(
                f"[{f.severity.style_color}]{f.severity.value}[/]",
                f.category.value,
                f.title,
                f.target,
                f.source_module,
            )
        console.print(table)
    else:
        console.print("[dim]No findings recorded.[/dim]")

    # Export
    gen = ReportGenerator(result)
    if args.output:
        p = gen.save_report(args.output)
        console.print(f"[bold green]✔ Saved Markdown report to:[/] {p}")

    if args.json:
        p = gen.save_report(args.json)
        console.print(f"[bold green]✔ Saved JSON report to:[/] {p}")

    if args.html:
        p = gen.save_report(args.html)
        console.print(f"[bold green]✔ Saved HTML report to:[/] {p}")

    return 0


async def run_cli_verify(args: argparse.Namespace) -> int:
    console = Console()
    try:
        profile = ClientProfile(
            client_type=ClientType(args.type),
            name=args.name,
            company=args.company,
            domain=args.domain,
            email=args.email,
            phone=args.phone,
            address=args.address,
        )
        depth = InvestigationDepth(args.depth)
        target = Target.from_client_profile(profile, depth=depth)
    except Exception as e:
        console.print(f"[bold red]Target Initialization Error:[/] {e}")
        return 1

    subject_desc = profile.name or profile.company or target.domain
    console.print(
        Panel(
            f"[bold cyan]Sherlock Due Diligence & Identity Risk Suite[/bold cyan]\n"
            f"Mode: [bold magenta]{profile.client_type.value.upper()}[/bold magenta] | "
            f"Subject: [bold white]{subject_desc}[/bold white]\n"
            f"Email: {profile.email or '[dim]None[/dim]'} | "
            f"Phone: {profile.phone or '[dim]None[/dim]'} | "
            f"Company: {profile.company or '[dim]None[/dim]'} | "
            f"Domain: {profile.domain or '[dim]None[/dim]'}",
            title="Due Diligence Investigation Initialized",
            border_style="magenta",
        )
    )

    module_ids = ["due_diligence"]
    if target.domain and target.domain != "due-diligence.local":
        module_ids.extend(["dns_scanner", "rdap_scanner", "http_headers"])

    engine = SherlockEngine.from_module_ids(module_ids)

    with console.status(f"[bold green]Running due diligence audits on {subject_desc}...[/bold green]"):
        result = await engine.run(target)

    s = result.summary
    console.print()

    score_style = "green" if s.risk_score < 25 else ("yellow" if s.risk_score < 55 else "red")
    verdict = (
        "CLEARED / LOW RISK"
        if s.risk_score < 25
        else ("CAUTION / REQUIRES REVIEW" if s.risk_score < 55 else "HIGH RISK / RED FLAGS DETECTED")
    )

    console.print(
        Panel(
            f"[bold]Entity / Subject:[/] {subject_desc}\n"
            f"[bold]Audit Mode:[/] {profile.client_type.value.upper()}\n"
            f"[bold]Risk Assessment:[/] [{score_style}]{s.risk_score} / 100 ({verdict})[/{score_style}]\n"
            f"[bold]Findings Flagged:[/] {s.total_findings}\n"
            f"[bold]Duration:[/] {s.duration_seconds}s",
            title="[bold]Due Diligence Assessment Dossier[/bold]",
            border_style=score_style,
        )
    )

    if result.findings:
        table = Table(title="Identity & Fraud Risk Findings", show_lines=True)
        table.add_column("Severity", justify="center", width=10)
        table.add_column("Finding", style="bold")
        table.add_column("Details", style="dim")
        table.add_column("Remediation / Action", style="cyan")

        for f in result.findings:
            table.add_row(
                f"[{f.severity.style_color}]{f.severity.value}[/]",
                f.title,
                f.description,
                f.remediation or "[dim]N/A[/dim]",
            )
        console.print(table)
    else:
        console.print("[green]No risk flags or anomalies recorded.[/green]")

    # Export
    gen = ReportGenerator(result)
    if args.output:
        p = gen.save_report(args.output)
        console.print(f"[bold green]✔ Saved Markdown report to:[/] {p}")
    if args.json:
        p = gen.save_report(args.json)
        console.print(f"[bold green]✔ Saved JSON report to:[/] {p}")
    if args.html:
        p = gen.save_report(args.html)
        console.print(f"[bold green]✔ Saved HTML report to:[/] {p}")

    return 0


def list_modules():
    console = Console()
    table = Table(title="Available Sherlock OSINT Modules")
    table.add_column("Module ID", style="cyan")
    table.add_column("Name", style="bold")
    table.add_column("Category")
    table.add_column("Description")

    for mod in ALL_MODULES:
        table.add_row(mod.module_id, mod.name, mod.category.value, mod.description)

    console.print(table)


def main() -> None:
    args = parse_args()

    if args.command == "modules":
        list_modules()
        sys.exit(0)
    elif args.command == "scan":
        code = asyncio.run(run_cli_scan(args))
        sys.exit(code)
    elif args.command == "verify":
        code = asyncio.run(run_cli_verify(args))
        sys.exit(code)
    else:
        # Default with no args or 'tui' command is launching interactive TUI
        launch_tui()


if __name__ == "__main__":
    main()

