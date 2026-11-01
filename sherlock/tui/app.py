"""
Sherlock OSINT & Attack Surface Management - Textual TUI Application.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Markdown,
    ProgressBar,
    RichLog,
    Select,
    Static,
    TabbedContent,
    TabPane,
)

from ..context import InvestigationContext
from ..engine import SherlockEngine
from ..models import (
    Category,
    Finding,
    InvestigationDepth,
    InvestigationResult,
    Severity,
    Target,
)
from ..modules import ALL_MODULES, MODULE_MAP
from ..reports import ReportGenerator
from .widgets.finding_modal import FindingDetailModal


class SherlockTUI(App[None]):
    """Sherlock Defensive OSINT Terminal User Interface."""

    CSS_PATH = "style.tcss"
    TITLE = "Sherlock OSINT & Attack Surface Suite"
    SUB_TITLE = "Defensive Infrastructure & Security Posture Auditor"

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("r", "run_investigation", "Run Scan", show=True),
        Binding("c", "cancel_investigation", "Cancel", show=True),
        Binding("e", "export_report", "Export Report", show=True),
    ]

    is_running = reactive(False)
    findings_list: List[Finding] = []
    seen_subdomains: Dict[str, str] = {}
    current_result: Optional[InvestigationResult] = None
    current_context: Optional[InvestigationContext] = None
    current_worker: Any = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        # Control Panel
        with Vertical(id="control-panel"):
            with Horizontal(id="target-row"):
                yield Label("Target Domain:", id="target-label")
                yield Input(placeholder="e.g. example.com or cloudflare.com", id="target-input")
                yield Label("Depth:", id="depth-label")
                yield Select[str](
                    [
                        ("Quick Scan", InvestigationDepth.QUICK.value),
                        ("Standard Audit", InvestigationDepth.STANDARD.value),
                        ("Deep Surface Mapping", InvestigationDepth.DEEP.value),
                    ],
                    value=InvestigationDepth.STANDARD.value,
                    allow_blank=False,
                    id="depth-select",
                )

            with Horizontal(id="buttons-row"):
                yield Button("▶ Run Audit", variant="primary", id="btn-run")
                yield Button("⏹ Cancel", variant="error", id="btn-cancel", disabled=True)
                yield Button("💾 Export Report", variant="success", id="btn-export", disabled=True)
                yield Button("🧹 Clear", variant="default", id="btn-clear")

            with Horizontal(id="modules-row"):
                yield Label("Active Modules:", id="modules-label")
                for mod_cls in ALL_MODULES:
                    yield Checkbox(
                        mod_cls.name.split(" ")[0],
                        value=True,
                        id=f"chk-{mod_cls.module_id}",
                    )

        # Stats / Metrics Bar
        with Horizontal(id="stats-bar"):
            with Vertical(classes="stat-card"):
                yield Label("TARGET", classes="stat-title")
                yield Label("None", id="stat-target", classes="stat-value")
            with Vertical(classes="stat-card"):
                yield Label("STATUS", classes="stat-title")
                yield Label("IDLE", id="stat-status", classes="stat-value")
            with Vertical(classes="stat-card"):
                yield Label("RISK SCORE", classes="stat-title")
                yield Label("0 / 100", id="stat-risk", classes="stat-value stat-risk-low")
            with Vertical(classes="stat-card"):
                yield Label("FINDINGS", classes="stat-title")
                yield Label("0", id="stat-findings", classes="stat-value")
            with Vertical(classes="stat-card"):
                yield Label("SUBDOMAINS", classes="stat-title")
                yield Label("0", id="stat-subs", classes="stat-value")

        # Progress bar area
        with Horizontal(id="progress-container"):
            yield ProgressBar(total=100, show_eta=False, id="progress-bar")
            yield Label("Ready.", id="status-label")

        # Main Workspace Tabs
        with Container(id="main-container"):
            with TabbedContent():
                with TabPane("Findings Table", id="tab-findings"):
                    with Horizontal(id="filter-bar"):
                        yield Label("Filter Severity:", id="filter-label")
                        yield Select[str](
                            [
                                ("All Severities", "ALL"),
                                ("Critical Only", "CRITICAL"),
                                ("High & Above", "HIGH_PLUS"),
                                ("Medium & Above", "MED_PLUS"),
                                ("Low & Above", "LOW_PLUS"),
                                ("Info Only", "INFO"),
                            ],
                            value="ALL",
                            allow_blank=False,
                            id="severity-filter",
                        )
                        yield Input(placeholder="Search findings...", id="search-filter")

                    yield DataTable(id="findings-table", cursor_type="row")

                with TabPane("Live Activity Log", id="tab-log"):
                    yield RichLog(id="activity-log", highlight=True, markup=True)

                with TabPane("Discovered Subdomains", id="tab-subs"):
                    yield DataTable(id="subdomains-table", cursor_type="row")

                with TabPane("Executive Summary", id="tab-summary"):
                    with VerticalScroll(id="summary-scroll"):
                        yield Markdown(
                            "# Sherlock OSINT Summary\n*Run an investigation to generate an attack surface report.*",
                            id="summary-markdown",
                        )

        yield Footer()

    def on_mount(self) -> None:
        # Initialize Findings DataTable
        table = self.query_one("#findings-table", DataTable)
        table.add_columns("ID", "Severity", "Category", "Title", "Target Asset", "Module")

        # Initialize Subdomains DataTable
        sub_table = self.query_one("#subdomains-table", DataTable)
        sub_table.add_columns("Discovered Subdomain", "Resolved IP(s) / Source")

        # Welcome message in activity log
        log = self.query_one("#activity-log", RichLog)
        log.write("[bold cyan]=== Sherlock Defensive OSINT & Attack Surface Suite Initialized ===[/bold cyan]")
        log.write("[dim]Enter a target corporate domain above and click 'Run Audit'.[/dim]\n")

    # Watchers
    def watch_is_running(self, running: bool) -> None:
        try:
            self.query_one("#btn-run", Button).disabled = running
            self.query_one("#btn-cancel", Button).disabled = not running
            self.query_one("#target-input", Input).disabled = running
            self.query_one("#depth-select", Select).disabled = running
            self.query_one("#stat-status", Label).update("SCANNING" if running else "IDLE")
        except Exception:
            pass

    # Button handlers
    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-run":
            self.action_run_investigation()
        elif bid == "btn-cancel":
            self.action_cancel_investigation()
        elif bid == "btn-export":
            self.action_export_report()
        elif bid == "btn-clear":
            self.action_clear_workspace()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "target-input" and not self.is_running:
            self.action_run_investigation()
        elif event.input.id == "search-filter":
            self.apply_table_filters()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "search-filter":
            self.apply_table_filters()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "severity-filter":
            self.apply_table_filters()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "findings-table" and event.row_key:
            row_idx_str = str(event.row_key.value)
            # Find finding by id
            for f in self.findings_list:
                if f.id == row_idx_str:
                    self.push_screen(FindingDetailModal(f))
                    break

    # Actions
    def action_run_investigation(self) -> None:
        if self.is_running:
            return

        target_input = self.query_one("#target-input", Input).value.strip()
        if not target_input:
            self.notify("Please enter a valid target domain first.", severity="warning")
            self.query_one("#target-input", Input).focus()
            return

        depth_val = self.query_one("#depth-select", Select).value or InvestigationDepth.STANDARD.value
        depth = InvestigationDepth(depth_val)

        try:
            target = Target(domain=target_input, depth=depth)
        except Exception as e:
            self.notify(f"Invalid target: {e}", severity="error")
            return

        # Check selected modules
        selected_module_ids = []
        for mod_cls in ALL_MODULES:
            chk = self.query_one(f"#chk-{mod_cls.module_id}", Checkbox)
            if chk.value:
                selected_module_ids.append(mod_cls.module_id)

        if not selected_module_ids:
            self.notify("Please select at least one module to execute.", severity="warning")
            return

        # Reset state for new run
        self.findings_list.clear()
        self.seen_subdomains.clear()
        table = self.query_one("#findings-table", DataTable)
        table.clear()
        sub_table = self.query_one("#subdomains-table", DataTable)
        sub_table.clear()

        self.query_one("#stat-target", Label).update(target.domain)
        self.query_one("#stat-findings", Label).update("0")
        self.query_one("#stat-subs", Label).update("0")
        self.query_one("#stat-risk", Label).update("0 / 100")
        self.query_one("#btn-export", Button).disabled = True

        log = self.query_one("#activity-log", RichLog)
        log.write(f"\n[bold green]>>> Launching audit against [white]{target.domain}[/white] (Depth: {target.depth.value})[/bold green]")

        # Launch background work
        self.current_worker = self.execute_engine_scan(target, selected_module_ids)

    def action_cancel_investigation(self) -> None:
        if self.is_running:
            if self.current_context:
                self.current_context.cancel()
            if self.current_worker and hasattr(self.current_worker, "cancel"):
                try:
                    self.current_worker.cancel()
                except Exception:
                    pass
            self.notify("Cancellation requested. Halting modules...", severity="warning")
            log = self.query_one("#activity-log", RichLog)
            log.write("[bold red][!] Investigation cancelled by user.[/bold red]")

    def action_clear_workspace(self) -> None:
        if self.is_running:
            self.notify("Cannot clear while scan is in progress.", severity="warning")
            return
        self.findings_list.clear()
        self.seen_subdomains.clear()
        self.current_result = None
        self.query_one("#findings-table", DataTable).clear()
        self.query_one("#subdomains-table", DataTable).clear()
        self.query_one("#stat-target", Label).update("None")
        self.query_one("#stat-status", Label).update("IDLE")
        self.query_one("#stat-risk", Label).update("0 / 100")
        self.query_one("#stat-findings", Label).update("0")
        self.query_one("#stat-subs", Label).update("0")
        self.query_one("#status-label", Label).update("Cleared.")
        self.query_one("#progress-bar", ProgressBar).progress = 0
        self.query_one("#summary-markdown", Markdown).update("# Sherlock OSINT Summary\n*Workspace reset.*")
        self.query_one("#btn-export", Button).disabled = True
        self.notify("Workspace cleared.")

    def action_export_report(self) -> None:
        if not self.current_result:
            self.notify("No investigation results available to export.", severity="warning")
            return

        reports_dir = Path("./reports")
        reports_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_name = self.current_result.target.domain.replace(".", "_")

        md_file = reports_dir / f"sherlock_{target_name}_{ts}.md"
        json_file = reports_dir / f"sherlock_{target_name}_{ts}.json"
        html_file = reports_dir / f"sherlock_{target_name}_{ts}.html"

        gen = ReportGenerator(self.current_result)
        gen.save_report(md_file)
        gen.save_report(json_file)
        gen.save_report(html_file)

        msg = f"Exported: {md_file.name}, {json_file.name}, {html_file.name}"
        self.notify(msg, severity="information", timeout=6)
        log = self.query_one("#activity-log", RichLog)
        log.write(f"[bold green]✔ Saved Markdown report to:[/] {md_file.resolve()}")
        log.write(f"[bold green]✔ Saved JSON report to:[/] {json_file.resolve()}")
        log.write(f"[bold green]✔ Saved HTML report to:[/] {html_file.resolve()}")

    @work(exclusive=True)
    async def execute_engine_scan(self, target: Target, module_ids: List[str]) -> None:
        self.is_running = True
        self.query_one("#progress-bar", ProgressBar).progress = 5
        self.query_one("#status-label", Label).update("Initializing modules...")

        context = InvestigationContext(target)
        self.current_context = context

        # Connect callbacks directly to methods (runs on the main asyncio event loop)
        def on_log(level: str, msg: str):
            self._handle_log(level, msg)

        def on_finding(finding: Finding):
            self._handle_finding(finding)

        def on_progress(mod: str, pct: float, status: str):
            self._handle_progress(mod, pct, status)

        context.on_log = on_log
        context.on_finding = on_finding
        context.on_progress = on_progress

        engine = SherlockEngine.from_module_ids(module_ids)

        try:
            result = await engine.run(target, context)
            self.current_result = result
            self._finalize_run(result)
        except asyncio.CancelledError:
            self.notify("Investigation cancelled.", severity="warning")
        except Exception as e:
            self.notify(f"Investigation error: {e}", severity="error")
        finally:
            self.is_running = False

    def _handle_log(self, level: str, msg: str) -> None:
        log = self.query_one("#activity-log", RichLog)
        ts = datetime.now().strftime("%H:%M:%S")
        color_map = {
            "info": "cyan",
            "warning": "yellow",
            "error": "bold red",
        }
        color = color_map.get(level.lower(), "white")
        log.write(f"[dim]{ts}[/dim] [{color}][{level.upper()}][/{color}] {msg}")

    def _should_display_finding(self, f: Finding) -> bool:
        sev_filter = self.query_one("#severity-filter", Select).value or "ALL"
        search_query = self.query_one("#search-filter", Input).value.strip().lower()

        if sev_filter == "CRITICAL" and f.severity != Severity.CRITICAL:
            return False
        if sev_filter == "HIGH_PLUS" and f.severity not in [Severity.CRITICAL, Severity.HIGH]:
            return False
        if sev_filter == "MED_PLUS" and f.severity not in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]:
            return False
        if sev_filter == "LOW_PLUS" and f.severity == Severity.INFO:
            return False
        if sev_filter == "INFO" and f.severity != Severity.INFO:
            return False

        if search_query:
            blob = f"{f.title} {f.description} {f.target} {f.category.value} {f.source_module}".lower()
            if search_query not in blob:
                return False

        return True

    def _handle_finding(self, finding: Finding) -> None:
        self.findings_list.append(finding)
        self.query_one("#stat-findings", Label).update(str(len(self.findings_list)))

        # Append single row to table if it matches current filter (avoids table clear flicker)
        if self._should_display_finding(finding):
            table = self.query_one("#findings-table", DataTable)
            sev_formatted = f"[{finding.severity.style_color}]{finding.severity.value}[/]"
            table.add_row(
                finding.id,
                sev_formatted,
                finding.category.value,
                finding.title,
                finding.target,
                finding.source_module,
                key=finding.id,
            )

        # Update subdomains table with deduplication
        sub_table = self.query_one("#subdomains-table", DataTable)
        new_subs: List[tuple[str, str]] = []

        if "subdomain" in finding.data:
            ips = ", ".join(finding.data.get("ips", [])) or "Resolved via DNS"
            new_subs.append((finding.data["subdomain"], ips))
        elif "subdomains" in finding.data and isinstance(finding.data["subdomains"], list):
            for sub in finding.data["subdomains"]:
                new_subs.append((sub, "Certificate Transparency Log"))

        for sub, source in new_subs:
            if sub not in self.seen_subdomains:
                self.seen_subdomains[sub] = source
                sub_table.add_row(sub, source, key=sub)

        self.query_one("#stat-subs", Label).update(str(len(self.seen_subdomains)))

    def _handle_progress(self, module_name: str, pct: float, status_text: str) -> None:
        pbar = self.query_one("#progress-bar", ProgressBar)
        pbar.progress = min(100.0, max(0.0, pct * 100))
        self.query_one("#status-label", Label).update(f"[{module_name}] {status_text}")

    def _finalize_run(self, result: InvestigationResult) -> None:
        self.query_one("#progress-bar", ProgressBar).progress = 100
        self.query_one("#status-label", Label).update("Investigation Completed.")
        self.query_one("#btn-export", Button).disabled = False

        # Update Risk Score styling
        score = result.summary.risk_score
        risk_label = self.query_one("#stat-risk", Label)
        risk_label.update(f"{score} / 100")
        risk_label.remove_class("stat-risk-low", "stat-risk-med", "stat-risk-high")
        if score < 30:
            risk_label.add_class("stat-risk-low")
        elif score < 60:
            risk_label.add_class("stat-risk-med")
        else:
            risk_label.add_class("stat-risk-high")

        # Update Markdown Summary Tab
        report_gen = ReportGenerator(result)
        self.query_one("#summary-markdown", Markdown).update(report_gen.to_markdown())

        self.notify(
            f"Audit finished: {result.summary.total_findings} findings, Risk Score: {score}/100",
            severity="information",
            timeout=5,
        )

    def apply_table_filters(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.clear()

        for f in self.findings_list:
            if not self._should_display_finding(f):
                continue

            sev_formatted = f"[{f.severity.style_color}]{f.severity.value}[/]"
            table.add_row(
                f.id,
                sev_formatted,
                f.category.value,
                f.title,
                f.target,
                f.source_module,
                key=f.id,
            )


def launch():
    app = SherlockTUI()
    app.run()


if __name__ == "__main__":
    launch()
