"""
Surface Web & Infrastructure Port Auditor.
Conducts safe, non-intrusive TCP connectivity checks on standard web and defensive service ports.
"""

from __future__ import annotations

import asyncio
from typing import Dict, List, Tuple
from ..context import InvestigationContext
from ..models import Category, Finding, InvestigationDepth, Severity, Target
from .base import BaseModule

PORT_DEFINITIONS: Dict[int, Tuple[str, str, Severity]] = {
    80: ("HTTP", "Standard cleartext web service", Severity.INFO),
    443: ("HTTPS", "Standard encrypted web service", Severity.INFO),
    8080: ("HTTP-Alt", "Alternative HTTP port (frequently administrative or proxy)", Severity.LOW),
    8443: ("HTTPS-Alt", "Alternative HTTPS port (often administrative or management interface)", Severity.LOW),
    8000: ("Dev-Web", "Common development web server port", Severity.MEDIUM),
    8888: ("Dashboard/Admin", "Common administrative or analytics dashboard port", Severity.MEDIUM),
    21: ("FTP", "File Transfer Protocol server", Severity.MEDIUM),
    22: ("SSH", "Secure Shell remote access service", Severity.INFO),
    25: ("SMTP", "Simple Mail Transfer Protocol server", Severity.INFO),
    587: ("SMTP-Submission", "Mail submission port", Severity.INFO),
    3306: ("MySQL", "Exposed relational database server", Severity.HIGH),
    3389: ("RDP", "Windows Remote Desktop Protocol service", Severity.HIGH),
    5432: ("PostgreSQL", "Exposed PostgreSQL database server", Severity.HIGH),
    6379: ("Redis", "Exposed in-memory data store", Severity.CRITICAL),
    9200: ("Elasticsearch", "Exposed search cluster endpoint", Severity.HIGH),
    27017: ("MongoDB", "Exposed NoSQL database service", Severity.HIGH),
}


class PortSurfaceScannerModule(BaseModule):
    module_id = "port_surface"
    name = "Surface Port Auditor"
    description = "Checks standard web and administrative ports to map exposed surface endpoints."
    category = Category.PORT_SURFACE

    async def run(self, target: Target, context: InvestigationContext) -> None:
        await context.log("info", f"[Port] Auditing standard surface ports for {target.domain}")

        if target.depth == InvestigationDepth.QUICK:
            ports_to_check = [80, 443]
        elif target.depth == InvestigationDepth.STANDARD:
            ports_to_check = [80, 443, 8080, 8443, 8000, 8888, 22]
        else:
            ports_to_check = list(PORT_DEFINITIONS.keys())

        open_ports: List[int] = []
        total = len(ports_to_check)

        async def check_port(port: int, idx: int):
            if context.cancelled:
                return
            await context.update_progress(self.name, idx / total, f"Checking port {port}...")
            try:
                # 2.0 second connection timeout
                conn = asyncio.open_connection(target.domain, port)
                reader, writer = await asyncio.wait_for(conn, timeout=2.5)
                writer.close()
                await writer.wait_closed()
                open_ports.append(port)

                service_name, desc, sev = PORT_DEFINITIONS.get(
                    port, (f"Port-{port}", "Open surface port", Severity.INFO)
                )

                await context.emit_finding(
                    Finding(
                        category=Category.PORT_SURFACE,
                        severity=sev,
                        title=f"Port {port} ({service_name}) Open & Accessible",
                        description=f"Host responds on TCP port {port} ({service_name}). {desc}.",
                        target=f"{target.domain}:{port}",
                        source_module=self.name,
                        data={"port": port, "service": service_name, "state": "open"},
                        remediation="Ensure only necessary ports are publicly reachable through firewall/security group rules."
                        if sev != Severity.INFO
                        else None,
                    )
                )
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                pass
            except Exception:
                pass

        tasks = [check_port(p, i) for i, p in enumerate(ports_to_check)]
        await asyncio.gather(*tasks)

        await context.update_progress(self.name, 1.0, f"Completed port audit ({len(open_ports)} open)")
        await context.log("info", f"[Port] Surface port audit complete. Open ports: {open_ports or 'None detected'}")
