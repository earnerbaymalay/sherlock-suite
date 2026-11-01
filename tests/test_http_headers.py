import pytest
from unittest.mock import AsyncMock, patch

from sherlock.context import InvestigationContext
from sherlock.models import Severity, Target
from sherlock.modules.http_headers import HTTPHeadersScannerModule


@pytest.mark.asyncio
async def test_http_headers_missing_hsts_and_csp():
    module = HTTPHeadersScannerModule()
    target = Target(domain="example.com")
    context = InvestigationContext(target)

    # Mock HTTPS response lacking HSTS & CSP, having version banner
    mock_https_resp = AsyncMock()
    mock_https_resp.headers = {
        "server": "Apache/2.4.41",
        "x-powered-by": "PHP/7.4.3",
    }

    # Mock HTTP response redirecting cleanly
    mock_http_resp = AsyncMock()
    mock_http_resp.status_code = 301
    mock_http_resp.headers = {"location": "https://example.com"}

    async def mock_get(url, **kwargs):
        if url.startswith("https://"):
            return mock_https_resp
        return mock_http_resp

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        await module.run(target, context)

    findings = context.findings
    assert any(f.severity == Severity.MEDIUM and "Missing Strict-Transport-Security" in f.title for f in findings)
    assert any(f.severity == Severity.MEDIUM and "Missing Content-Security-Policy" in f.title for f in findings)
    assert any("Server Technology Disclosed" in f.title for f in findings)
    assert any("Backend Technology Disclosed" in f.title for f in findings)
    assert any(f.severity == Severity.INFO and "HTTP to HTTPS Redirection Enforced" in f.title for f in findings)


@pytest.mark.asyncio
async def test_http_headers_secure():
    module = HTTPHeadersScannerModule()
    target = Target(domain="secure.example.com")
    context = InvestigationContext(target)

    mock_https_resp = AsyncMock()
    mock_https_resp.headers = {
        "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
    }

    mock_http_resp = AsyncMock()
    mock_http_resp.status_code = 301
    mock_http_resp.headers = {"location": "https://secure.example.com"}

    async def mock_get(url, **kwargs):
        if url.startswith("https://"):
            return mock_https_resp
        return mock_http_resp

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        await module.run(target, context)

    findings = context.findings
    assert any("Strict-Transport-Security (HSTS) Configured" in f.title for f in findings)
    assert any("Content-Security-Policy (CSP) Active" in f.title for f in findings)
    assert any("X-Frame-Options Configured" in f.title for f in findings)
    assert any("nosniff Active" in f.title for f in findings)
    assert not any(f.severity == Severity.MEDIUM for f in findings)


@pytest.mark.asyncio
async def test_http_headers_ssl_cert_error():
    import httpx
    module = HTTPHeadersScannerModule()
    target = Target(domain="untrusted-root.badssl.com")
    context = InvestigationContext(target)

    mock_resp = AsyncMock()
    mock_resp.headers = {"server": "nginx"}

    call_count = 0

    async def mock_get(url, **kwargs):
        nonlocal call_count
        call_count += 1
        # The first call is verify=True, simulate SSL certificate validation error
        if kwargs.get("verify") is True or call_count == 1:
            raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")
        return mock_resp

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        await module.run(target, context)

    findings = context.findings
    assert any(f.severity == Severity.HIGH and "Invalid or Untrusted TLS/SSL Certificate" in f.title for f in findings)
