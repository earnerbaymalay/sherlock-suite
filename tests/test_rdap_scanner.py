import pytest
from unittest.mock import AsyncMock, patch

from sherlock.context import InvestigationContext
from sherlock.models import Severity, Target
from sherlock.modules.rdap_scanner import RDAPScannerModule


@pytest.mark.asyncio
async def test_rdap_scanner_imminent_expiration():
    module = RDAPScannerModule()
    target = Target(domain="expiring-soon.com")
    context = InvestigationContext(target)

    mock_rdap_data = {
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "NameCheap, Inc."]]],
            }
        ],
        "events": [
            {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2026-11-05T00:00:00Z"},  # Expiring soon
        ],
        "status": ["active"],
    }

    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.json = lambda: mock_rdap_data

    with patch("httpx.AsyncClient.get", return_value=mock_resp):
        await module.run(target, context)

    findings = context.findings
    assert any("Imminent Domain Expiration" in f.title for f in findings)
    assert any("Domain Missing Client/Server Transfer Lock" in f.title for f in findings)


@pytest.mark.asyncio
async def test_rdap_scanner_redemption_and_dnssec():
    module = RDAPScannerModule()
    target = Target(domain="expired-domain.org")
    context = InvestigationContext(target)

    mock_rdap_data = {
        "entities": [],
        "events": [
            {"eventAction": "registration", "eventDate": "2015-01-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2026-10-01T00:00:00Z"},
        ],
        "status": ["redemptionPeriod", "serverHold"],
        "secureDNS": {"delegationSigned": False},
        "nameservers": [{"ldhName": "ns1.expired-domain.org"}],
    }

    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.json = lambda: mock_rdap_data

    with patch("httpx.AsyncClient.get", return_value=mock_resp):
        await module.run(target, context)

    findings = context.findings
    assert any(f.severity == Severity.HIGH and "Redemption" in f.title for f in findings)
    assert any(f.severity == Severity.LOW and "DNSSEC" in f.title for f in findings)
