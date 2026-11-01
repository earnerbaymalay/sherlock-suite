import pytest
from sherlock.tui.app import SherlockTUI
from textual.widgets import Button, DataTable, Input, Label, ProgressBar, RichLog, Select


@pytest.mark.asyncio
async def test_tui_mount_and_initial_state():
    app = SherlockTUI()
    async with app.run_test() as pilot:
        # Check title & initial widgets
        assert app.query_one("#target-input", Input) is not None
        assert app.query_one("#depth-select", Select) is not None
        assert app.query_one("#btn-run", Button) is not None
        assert app.query_one("#btn-cancel", Button).disabled is True
        assert app.query_one("#btn-export", Button).disabled is True
        assert app.query_one("#findings-table", DataTable) is not None
        assert app.query_one("#activity-log", RichLog) is not None
        assert app.query_one("#progress-bar", ProgressBar) is not None

        # Verify clear button behavior
        clear_btn = app.query_one("#btn-clear", Button)
        await pilot.click(clear_btn)
        findings_lbl = app.query_one("#stat-findings", Label)
        assert str(findings_lbl.render()) == "0"


@pytest.mark.asyncio
async def test_tui_input_validation():
    app = SherlockTUI()
    async with app.run_test() as pilot:
        # Click run with empty input
        run_btn = app.query_one("#btn-run", Button)
        await pilot.click(run_btn)
        # Scan should not run
        assert app.is_running is False


@pytest.mark.asyncio
async def test_tui_full_scan_execution_and_findings():
    app = SherlockTUI()
    async with app.run_test() as pilot:
        inp = app.query_one("#target-input", Input)
        inp.value = "example.com"

        # Disable all modules except port scanner to make test fast and reliable
        for mid in ["dns_scanner", "crtsh_scanner", "http_headers", "rdap_scanner"]:
            chk = app.query_one(f"#chk-{mid}")
            chk.value = False

        run_btn = app.query_one("#btn-run", Button)
        await pilot.click(run_btn)

        # Wait for scan to complete without raising RuntimeError
        for _ in range(50):
            await pilot.pause(0.1)
            if not app.is_running:
                break

        assert app.is_running is False
        assert app.current_result is not None
        assert app.current_result.summary.total_findings >= 1

        # Check export button is now enabled
        export_btn = app.query_one("#btn-export", Button)
        assert export_btn.disabled is False

        # Test search filter input
        search_filter = app.query_one("#search-filter", Input)
        search_filter.value = "nonexistent_term_xyz"
        await pilot.pause(0.2)
        table = app.query_one("#findings-table", DataTable)
        assert table.row_count == 0

        # Reset search filter
        search_filter.value = ""
        await pilot.pause(0.2)
        assert table.row_count == len(app.findings_list)

        # Test export report
        await pilot.click(export_btn)


@pytest.mark.asyncio
async def test_tui_cancellation():
    app = SherlockTUI()
    async with app.run_test() as pilot:
        inp = app.query_one("#target-input", Input)
        inp.value = "example.com"
        run_btn = app.query_one("#btn-run", Button)
        await pilot.click(run_btn)
        assert app.is_running is True

        cancel_btn = app.query_one("#btn-cancel", Button)
        await pilot.click(cancel_btn)
        await pilot.pause(0.2)
        assert app.current_context.cancelled is True
