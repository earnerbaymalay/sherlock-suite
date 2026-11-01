import asyncio
import pytest
from unittest.mock import AsyncMock, patch

from sherlock.context import InvestigationContext
from sherlock.models import InvestigationDepth, Severity, Target
from sherlock.modules.port_surface import PortSurfaceScannerModule


@pytest.mark.asyncio
async def test_port_surface_detects_open_ports():
    module = PortSurfaceScannerModule()
    target = Target(domain="example.com", depth=InvestigationDepth.QUICK)
    context = InvestigationContext(target)

    async def mock_open_conn(host, port):
        if port == 443:
            mock_writer = AsyncMock()
            mock_writer.close = MagicMock = lambda: None
            mock_writer.wait_closed = AsyncMock()
            return (AsyncMock(), mock_writer)
        raise ConnectionRefusedError()

    with patch("asyncio.open_connection", side_effect=mock_open_conn):
        await module.run(target, context)

    findings = context.findings
    assert any("Port 443 (HTTPS) Open" in f.title for f in findings)
    assert not any("Port 80 " in f.title for f in findings)
