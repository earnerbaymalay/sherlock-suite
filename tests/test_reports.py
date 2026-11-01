import json
from datetime import datetime, timezone
import pytest

from sherlock.models import Category, Finding, InvestigationResult, Severity, Target
from sherlock.reports import ReportGenerator


def test_report_generation(tmp_path):
    target = Target(domain="corp-test.com")
    f = Finding(
        category=Category.DNS,
        severity=Severity.HIGH,
        title="Insecure SPF",
        description="SPF +all configured",
        target="corp-test.com",
        source_module="dns_scanner",
        remediation="Set -all",
    )
    t0 = datetime.now(timezone.utc)
    res = InvestigationResult.create(
        target=target,
        findings=[f],
        modules_executed=["dns_scanner"],
        start_time=t0,
        end_time=t0,
    )

    gen = ReportGenerator(res)

    # Markdown test
    md = gen.to_markdown()
    assert "# Sherlock OSINT Investigation Report: corp-test.com" in md
    assert "[HIGH] Insecure SPF" in md
    assert "Set -all" in md

    # JSON test
    json_str = gen.to_json()
    data = json.loads(json_str)
    assert data["target"]["domain"] == "corp-test.com"
    assert data["summary"]["risk_score"] == 30

    # File saving
    md_file = tmp_path / "report.md"
    json_file = tmp_path / "report.json"
    html_file = tmp_path / "report.html"

    # HTML test
    html_str = gen.to_html()
    assert "<!DOCTYPE html>" in html_str
    assert "corp-test.com" in html_str
    assert "Insecure SPF" in html_str
    assert "Set -all" in html_str

    gen.save_report(md_file)
    gen.save_report(json_file)
    gen.save_report(html_file)

    assert md_file.exists()
    assert json_file.exists()
    assert html_file.exists()
