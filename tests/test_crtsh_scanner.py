import pytest
from unittest.mock import AsyncMock, patch
import httpx

from sherlock.context import InvestigationContext
from sherlock.models import Severity, Target
from sherlock.modules.crtsh_scanner import CrtShScannerModule


@pytest.mark.asyncio
async def test_crtsh_scanner_success():
    module = CrtShScannerModule()
    target = Target(domain="example.com")
    context = InvestigationContext(target)

    mock_records = [
        {
            "name_value": "api.example.com\nexample.com",
            "common_name": "api.example.com",
            "issuer_name": "Let's Encrypt",
            "not_after": "2030-01-01T00:00:00",
        },
        {
            "name_value": "*.dev.example.com",
            "common_name": "*.dev.example.com",
            "issuer_name": "DigiCert",
            "not_after": "2020-01-01T00:00:00",  # Expired
        },
    ]

    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.json = lambda: mock_records

    with patch("httpx.AsyncClient.get", return_value=mock_resp):
        await module.run(target, context)

    findings = context.findings
    assert any("Discovered" in f.title and "Subdomains" in f.title for f in findings)
    # dev.example.com should trigger the exposed sensitive hostnames finding
    assert any(f.severity == Severity.LOW and "Exposed Non-Production" in f.title for f in findings)
    assert "api.example.com" in context.discovered_subdomains
    assert "dev.example.com" in context.discovered_subdomains


@pytest.mark.asyncio
async def test_crtsh_scanner_timeout_handling():
    module = CrtShScannerModule()
    target = Target(domain="example.com")
    context = InvestigationContext(target)

    with patch("httpx.AsyncClient.get", side_effect=httpx.TimeoutException("timeout")):
        await module.run(target, context)

    findings = context.findings
    assert any("No Public CT Log Entries Retrieved" in f.title for f in findings)
