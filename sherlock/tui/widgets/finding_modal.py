"""
Modal Dialog for inspecting individual Sherlock finding details.
"""

from __future__ import annotations

import json
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Markdown, Static
from ...models import Finding


class FindingDetailModal(ModalScreen[None]):
    """Modal screen displaying detailed information and remediation for a Finding."""

    BINDINGS = [
        Binding("escape", "dismiss", "Close", show=True),
    ]

    CSS = """
    FindingDetailModal {
        align: center middle;
        background: rgba(0, 0, 0, 0.7);
    }

    #finding-dialog {
        width: 85%;
        max-width: 100;
        height: 80%;
        background: $surface;
        border: heavy $primary;
        padding: 1 2;
    }

    #modal-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
        border-bottom: solid $primary;
    }

    .meta-label {
        font-weight: bold;
        color: $secondary;
        width: 16;
    }

    .meta-row {
        height: auto;
        margin-bottom: 0;
    }

    #remediation-box {
        margin-top: 1;
        padding: 1;
        background: $panel;
        border: solid $warning;
    }

    #json-box {
        margin-top: 1;
        padding: 1;
        background: $background;
        border: dashed $secondary;
        max-height: 12;
    }

    #modal-buttons {
        margin-top: 1;
        align: right middle;
    }
    """

    def __init__(self, finding: Finding):
        super().__init__()
        self.finding = finding

    def compose(self) -> ComposeResult:
        f = self.finding
        with Vertical(id="finding-dialog"):
            yield Label(f"[{f.severity.value}] {f.title}", id="modal-title")
            with VerticalScroll():
                with Horizontal(classes="meta-row"):
                    yield Label("Category:", classes="meta-label")
                    yield Label(f.category.value)
                with Horizontal(classes="meta-row"):
                    yield Label("Severity:", classes="meta-label")
                    yield Label(f"[{f.severity.style_color}]{f.severity.value}[/]")
                with Horizontal(classes="meta-row"):
                    yield Label("Target Asset:", classes="meta-label")
                    yield Label(f.target)
                with Horizontal(classes="meta-row"):
                    yield Label("Source Module:", classes="meta-label")
                    yield Label(f.source_module)
                with Horizontal(classes="meta-row"):
                    yield Label("Timestamp:", classes="meta-label")
                    yield Label(f.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"))

                yield Label("\nDescription:", classes="meta-label")
                yield Static(f.description)

                if f.remediation:
                    with Container(id="remediation-box"):
                        yield Label("[bold yellow]Remediation Recommendation:[/bold yellow]")
                        yield Static(f.remediation)

                if f.data:
                    with Container(id="json-box"):
                        yield Label("[bold cyan]Raw Finding Data (JSON):[/bold cyan]")
                        yield Static(json.dumps(f.data, indent=2))

            with Horizontal(id="modal-buttons"):
                yield Button("Close (Esc)", variant="primary", id="close-btn")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close-btn":
            self.dismiss()

    def key_escape(self) -> None:
        self.dismiss()
