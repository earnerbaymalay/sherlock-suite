"""
Certificate Transparency Log Scanner (crt.sh).
Discovers public certificates, SAN entries, historical hostnames, and exposed attack surface.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Dict, List, Set
import httpx

from ..context import InvestigationContext
from ..models import Category, Finding, Severity, Target
from .base import BaseModule


class CrtShScannerModule(BaseModule):
    module_id = "crtsh_scanner"
    name = "Certificate Transparency Logs (crt.sh)"
    description = "Queries public CT logs to map all issued SSL/TLS certificates and historical subdomains."
    category = Category.CERTIFICATE

    CRTSH_URL = "https://crt.sh/"

    async def run(self, target: Target, context: InvestigationContext) -> None:
        await context.log("info", f"[crt.sh] Querying public Certificate Transparency logs for %{target.domain}")
        await context.update_progress(self.name, 0.1, "Connecting to crt.sh...")

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Sherlock-OSINT-Suite/1.0",
            "Accept": "application/json",
        }

        records: List[Dict] = []
        timeout = httpx.Timeout(connect=10.0, read=target.timeout, write=5.0, pool=5.0)

        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            # Query wildcard query
            params = {"q": f"%.{target.domain}", "output": "json"}
            try:
                resp = await client.get(self.CRTSH_URL, params=params, headers=headers)
                if resp.status_code == 200:
                    try:
                        records = resp.json()
                    except json.JSONDecodeError:
                        await context.log("warning", "[crt.sh] JSON parsing failed from crt.sh response")
                else:
                    await context.log("warning", f"[crt.sh] HTTP {resp.status_code} received from crt.sh")
            except httpx.TimeoutException:
                await context.log("warning", "[crt.sh] Request timed out while querying crt.sh")
            except Exception as e:
                await context.log("warning", f"[crt.sh] Connection failed: {e}")

            # If wildcard returned nothing or failed, try exact query
            if not records and not context.cancelled:
                try:
                    params_exact = {"q": target.domain, "output": "json"}
                    resp2 = await client.get(self.CRTSH_URL, params=params_exact, headers=headers)
                    if resp2.status_code == 200:
                        records = resp2.json()
                except Exception:
                    pass

        if context.cancelled:
            return

        await context.update_progress(self.name, 0.6, "Processing certificate records...")

        if not records:
            await context.emit_finding(
                Finding(
                    category=Category.CERTIFICATE,
                    severity=Severity.INFO,
                    title="No Public CT Log Entries Retrieved",
                    description=f"crt.sh returned 0 records or was temporarily unreachable for {target.domain}.",
                    target=target.domain,
                    source_module=self.name,
                    data={"count": 0},
                )
            )
            await context.update_progress(self.name, 1.0, "Completed")
            return

        unique_subdomains: Set[str] = set()
        issuers: Set[str] = set()
        now = datetime.now(timezone.utc)
        expired_count = 0
        wildcard_count = 0

        for item in records:
            name_val = item.get("name_value", "")
            common_name = item.get("common_name", "")
            issuer = item.get("issuer_name", "Unknown")
            issuers.add(issuer)

            # name_val can contain multiple names separated by newlines
            raw_names = name_val.split("\n") if name_val else []
            if common_name:
                raw_names.append(common_name)

            for name in raw_names:
                name = name.strip().lower()
                if not name or "@" in name or " " in name:
                    continue
                if name.startswith("*."):
                    wildcard_count += 1
                    name = name[2:]  # strip *.

                if name == target.domain or name.endswith(f".{target.domain}"):
                    unique_subdomains.add(name)

            # Check expiration
            not_after_str = item.get("not_after")
            if not_after_str:
                try:
                    # ISO format parsing
                    not_after = datetime.fromisoformat(not_after_str.replace("Z", "+00:00"))
                    if not_after < now:
                        expired_count += 1
                except Exception:
                    pass

        # Emit summary finding of subdomains discovered
        sorted_subdomains = sorted(list(unique_subdomains))
        await context.emit_finding(
            Finding(
                category=Category.CERTIFICATE,
                severity=Severity.INFO,
                title=f"Discovered {len(sorted_subdomains)} Subdomains via CT Logs",
                description=(
                    f"Identified {len(sorted_subdomains)} unique hostnames associated with {target.domain} "
                    f"across {len(records)} public transparency log entries."
                ),
                target=target.domain,
                source_module=self.name,
                data={
                    "total_certificates": len(records),
                    "subdomains_count": len(sorted_subdomains),
                    "subdomains": sorted_subdomains,
                    "issuers_sample": list(issuers)[:5],
                    "wildcards_observed": wildcard_count,
                    "expired_certs_observed": expired_count,
                },
            )
        )

        # Highlight potential development/internal subdomains exposed in CT logs
        sensitive_keywords = ["dev", "stage", "staging", "test", "internal", "corp", "vpn", "admin", "preprod", "uat", "k8s"]
        sensitive_discovered = [
            sub for sub in sorted_subdomains if any(kw in sub.split(".")[0] for kw in sensitive_keywords)
        ]
        if sensitive_discovered:
            await context.emit_finding(
                Finding(
                    category=Category.CERTIFICATE,
                    severity=Severity.LOW,
                    title="Exposed Non-Production / Sensitive Subdomains in CT Logs",
                    description=(
                        f"Certificate logs publicly reveal {len(sensitive_discovered)} development, internal, or administrative hostnames: "
                        f"{', '.join(sensitive_discovered[:5])}{'...' if len(sensitive_discovered) > 5 else ''}. "
                        "Public CT logs are monitored continuously by attackers to map staging and test environments."
                    ),
                    target=target.domain,
                    source_module=self.name,
                    data={"sensitive_subdomains": sensitive_discovered},
                    remediation="Ensure non-production hostnames require internal network access / VPN or zero-trust authentication.",
                )
            )

        await context.update_progress(self.name, 1.0, f"Found {len(sorted_subdomains)} subdomains in CT logs")
        await context.log("info", f"[crt.sh] Completed CT log analysis. Total subdomains: {len(sorted_subdomains)}")
