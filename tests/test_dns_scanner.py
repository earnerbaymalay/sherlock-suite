import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import dns.resolver

from sherlock.context import InvestigationContext
from sherlock.models import Category, InvestigationDepth, Severity, Target
from sherlock.modules.dns_scanner import DNSScannerModule


class MockRdata:
    def __init__(self, text):
        self._text = text

    def to_text(self):
        return self._text


class MockAnswer:
    def __init__(self, records, ttl=300):
        self.records = [MockRdata(r) for r in records]
        self.ttl = ttl

    def __iter__(self):
        return iter(self.records)


@pytest.mark.asyncio
async def test_dns_scanner_spf_insecure():
    module = DNSScannerModule()
    target = Target(domain="example.com", depth=InvestigationDepth.QUICK)
    context = InvestigationContext(target)

    async def mock_resolve(qname, rdtype):
        if rdtype == "TXT":
            return MockAnswer(["v=spf1 +all"])
        elif rdtype == "A":
            return MockAnswer(["93.184.216.34"])
        elif rdtype == "CAA":
            raise dns.resolver.NoAnswer()
        raise dns.resolver.NXDOMAIN()

    with patch.object(module, "_get_resolver") as mock_get_res:
        mock_res = MagicMock()
        mock_res.resolve = AsyncMock(side_effect=mock_resolve)
        mock_get_res.return_value = mock_res

        await module.run(target, context)

    findings = context.findings
    assert any(f.severity == Severity.HIGH and "Insecure SPF" in f.title for f in findings)
    assert any(f.severity == Severity.LOW and "Missing CAA" in f.title for f in findings)


@pytest.mark.asyncio
async def test_dns_scanner_dmarc_none():
    module = DNSScannerModule()
    target = Target(domain="example.com", depth=InvestigationDepth.QUICK)
    context = InvestigationContext(target)

    async def mock_resolve(qname, rdtype):
        if "_dmarc" in qname and rdtype == "TXT":
            return MockAnswer(["v=DMARC1; p=none; rua=mailto:d@example.com"])
        if rdtype == "TXT":
            return MockAnswer(["v=spf1 -all"])
        raise dns.resolver.NoAnswer()

    with patch.object(module, "_get_resolver") as mock_get_res:
        mock_res = MagicMock()
        mock_res.resolve = AsyncMock(side_effect=mock_resolve)
        mock_get_res.return_value = mock_res

        await module.run(target, context)

    findings = context.findings
    assert any(f.severity == Severity.LOW and "Permissive DMARC" in f.title for f in findings)
    assert any(f.severity == Severity.INFO and "Valid SPF" in f.title for f in findings)


@pytest.mark.asyncio
async def test_dns_scanner_multiple_spf_records():
    module = DNSScannerModule()
    target = Target(domain="example.com", depth=InvestigationDepth.QUICK)
    context = InvestigationContext(target)

    async def mock_resolve(qname, rdtype):
        if rdtype == "TXT":
            return MockAnswer(["v=spf1 include:_spf.google.com ~all", "v=spf1 include:mail.sendgrid.net -all"])
        raise dns.resolver.NoAnswer()

    with patch.object(module, "_get_resolver") as mock_get_res:
        mock_res = MagicMock()
        mock_res.resolve = AsyncMock(side_effect=mock_resolve)
        mock_get_res.return_value = mock_res

        await module.run(target, context)

    findings = context.findings
    assert any(f.severity == Severity.HIGH and "Multiple SPF Records" in f.title for f in findings)


@pytest.mark.asyncio
async def test_dns_scanner_chunked_txt_record():
    module = DNSScannerModule()
    target = Target(domain="example.com", depth=InvestigationDepth.QUICK)
    context = InvestigationContext(target)

    class MockChunkedRdata:
        def __init__(self, strings):
            self.strings = [s.encode("utf-8") for s in strings]

        def to_text(self):
            return " ".join(f'"{s}"' for s in [x.decode("utf-8") for x in self.strings])

    class MockChunkedAnswer:
        def __init__(self, chunked_lists):
            self.records = [MockChunkedRdata(cl) for cl in chunked_lists]
            self.ttl = 300

        def __iter__(self):
            return iter(self.records)

    async def mock_resolve(qname, rdtype):
        if rdtype == "TXT":
            # Long SPF split into 2 chunks
            return MockChunkedAnswer([["v=spf1 include:first.com", " include:second.com -all"]])
        raise dns.resolver.NoAnswer()

    with patch.object(module, "_get_resolver") as mock_get_res:
        mock_res = MagicMock()
        mock_res.resolve = AsyncMock(side_effect=mock_resolve)
        mock_get_res.return_value = mock_res

        await module.run(target, context)

    findings = context.findings
    assert any(f.severity == Severity.INFO and "Valid SPF" in f.title for f in findings)
    spf_finding = next(f for f in findings if "Valid SPF" in f.title)
    assert "include:first.com include:second.com -all" in spf_finding.data["spf_record"]
