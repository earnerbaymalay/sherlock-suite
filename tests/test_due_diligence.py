"""
Unit and integration tests for Sherlock Due Diligence & Client Risk Auditor.
Tests Person vs Business modes, disposable email checks, VOIP and phone line audits,
Australian Business Register (ABR) trust identification, court mention screening, and CMRA detection.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from sherlock.models import (
    Category,
    ClientProfile,
    ClientType,
    InvestigationDepth,
    Severity,
    Target,
)
from sherlock.context import InvestigationContext
from sherlock.modules.due_diligence import (
    DueDiligenceModule,
    DISPOSABLE_EMAIL_DOMAINS,
    FREEMAIL_DOMAINS,
)


def test_client_profile_initialization():
    prof = ClientProfile(
        client_type=ClientType.PERSON,
        name="Jane Doe",
        email="jane@example.com",
        phone="+61412345678",
        company="Acme Corp",
    )
    assert prof.client_type == ClientType.PERSON
    assert prof.name == "Jane Doe"
    assert prof.email == "jane@example.com"
    assert prof.phone == "+61412345678"

    target = Target.from_client_profile(prof)
    assert target.domain == "example.com"
    assert target.client_profile.name == "Jane Doe"


def test_target_from_profile_fallback_domain():
    prof = ClientProfile(
        client_type=ClientType.BUSINESS,
        company="Test Company",
        phone="+61298765432",
    )
    target = Target.from_client_profile(prof)
    assert target.domain == "due-diligence.local"


@pytest.mark.asyncio
async def test_due_diligence_disposable_email():
    module = DueDiligenceModule()
    prof = ClientProfile(
        client_type=ClientType.PERSON,
        name="Scam Actor",
        email="burner@10minutemail.com",
    )
    target = Target.from_client_profile(prof)
    context = InvestigationContext(target=target)

    await module.run(target, context)

    disposable_findings = [
        f for f in context.findings
        if f.title == "Disposable / Burner Email Service Detected"
    ]
    assert len(disposable_findings) == 1
    assert disposable_findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_due_diligence_phone_audit_valid_carrier():
    module = DueDiligenceModule()
    # Australian landline format
    prof = ClientProfile(
        client_type=ClientType.PERSON,
        name="Alice Citizen",
        phone="+61298765432",
    )
    target = Target.from_client_profile(prof)
    context = InvestigationContext(target=target)

    await module.run(target, context)

    phone_findings = [
        f for f in context.findings
        if "Telecom Carrier" in f.title or "Phone Number" in f.title
    ]
    assert len(phone_findings) >= 1
    assert phone_findings[0].data.get("region") == "AU"


@pytest.mark.asyncio
async def test_due_diligence_cmra_virtual_office():
    module = DueDiligenceModule()
    prof = ClientProfile(
        client_type=ClientType.BUSINESS,
        company="Shell Holdings",
        address="Suite 400 PMB 123, Regus Office Tower",
    )
    target = Target.from_client_profile(prof)
    context = InvestigationContext(target=target)

    await module.run(target, context)

    cmra_findings = [
        f for f in context.findings
        if "Commercial Mail Receiving Agency" in f.title or "Virtual Office" in f.title
    ]
    assert len(cmra_findings) == 1
    assert cmra_findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_due_diligence_brand_typosquatting():
    module = DueDiligenceModule()
    prof = ClientProfile(
        client_type=ClientType.BUSINESS,
        company="Paypal Support",
        domain="paypa1.com",
    )
    target = Target(domain="paypa1.com", client_profile=prof)
    context = InvestigationContext(target=target)

    await module.run(target, context)

    impersonation_findings = [
        f for f in context.findings
        if "Brand Impersonation" in f.title
    ]
    assert len(impersonation_findings) >= 1
    assert impersonation_findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_due_diligence_abr_trust_detection():
    module = DueDiligenceModule()
    prof = ClientProfile(
        client_type=ClientType.BUSINESS,
        company="Smith Family Trust",
    )
    target = Target.from_client_profile(prof)
    context = InvestigationContext(target=target)

    # Mock ABR HTML response with a trust
    fake_html = """
    <table>
      <tr><th>ABN</th><th>Entity</th><th>Type</th><th>Location</th></tr>
      <tr>
        <td>12 345 678 901 Active</td>
        <td>The Smith Family Trust</td>
        <td>Discretionary Trading Trust</td>
        <td>2000 NSW</td>
      </tr>
    </table>
    """
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = fake_html

    with patch("httpx.AsyncClient.get", return_value=mock_resp):
        await module._check_abr_trusts("Smith Family Trust", None, target, context)

    trust_findings = [
        f for f in context.findings
        if "Australian Trust" in f.title
    ]
    assert len(trust_findings) == 1
    assert "Discretionary Trading Trust" in trust_findings[0].description
    assert trust_findings[0].severity == Severity.INFO


@pytest.mark.asyncio
async def test_due_diligence_court_and_media_mock():
    module = DueDiligenceModule()
    prof = ClientProfile(
        client_type=ClientType.PERSON,
        name="Arthur Dent",
    )
    target = Target.from_client_profile(prof)
    context = InvestigationContext(target=target)

    fake_rss = """<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0">
      <channel>
        <item>
          <title>Arthur Dent sentenced in Federal Court fraud trial</title>
          <link>https://example.com/court-report</link>
          <pubDate>Mon, 01 Jan 2024 10:00:00 GMT</pubDate>
        </item>
      </channel>
    </rss>
    """
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = fake_rss.encode("utf-8")

    with patch("httpx.AsyncClient.get", return_value=mock_resp):
        await module._check_court_and_media("Arthur Dent", None, target, context)

    court_findings = [
        f for f in context.findings
        if "Adverse Court" in f.title or "Public Court" in f.title
    ]
    assert len(court_findings) == 1
    assert court_findings[0].severity == Severity.HIGH
    assert "fraud" in court_findings[0].description.lower()
