"""
DNS Attack Surface & Hygiene Scanner.
Audits DNS infrastructure, mail spoofing defenses (SPF, DMARC), CAA, and resolves subdomains.
"""

from __future__ import annotations

import asyncio
from typing import List, Optional
import dns.asyncresolver
import dns.exception
import dns.query
import dns.resolver
import dns.zone

from ..context import InvestigationContext
from ..models import Category, Finding, InvestigationDepth, Severity, Target
from .base import BaseModule

COMMON_PREFIXES = [
    "www",
    "mail",
    "api",
    "dev",
    "staging",
    "test",
    "portal",
    "vpn",
    "admin",
    "remote",
    "app",
    "auth",
    "cdn",
    "beta",
    "status",
    "corp",
    "internal",
    "git",
    "cloud",
    "mx",
]


class DNSScannerModule(BaseModule):
    module_id = "dns_scanner"
    name = "DNS Infrastructure & Mail Hygiene"
    description = "Queries DNS records (A, MX, NS, TXT, CAA), audits SPF/DMARC email defenses, and tests zone security."
    category = Category.DNS

    def __init__(self, nameservers: Optional[List[str]] = None):
        # Default public DNS resolvers (Cloudflare, Google) for reliability
        self.nameservers = nameservers or ["1.1.1.1", "8.8.8.8"]

    def _get_resolver(self, timeout: float) -> dns.asyncresolver.Resolver:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout
        if self.nameservers:
            resolver.nameservers = self.nameservers
        return resolver

    async def run(self, target: Target, context: InvestigationContext) -> None:
        await context.log("info", f"[DNS] Starting DNS audit for {target.domain}")
        resolver = self._get_resolver(timeout=min(target.timeout, 5.0))

        # 1. Standard DNS record queries
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"]
        total_steps = len(record_types) + 4
        current_step = 0

        txt_records: List[str] = []
        ns_servers: List[str] = []

        for rtype in record_types:
            if context.cancelled:
                return
            current_step += 1
            await context.update_progress(
                self.name, current_step / total_steps, f"Querying {rtype} records..."
            )
            try:
                answers = await resolver.resolve(target.domain, rtype)
                vals = []
                for rdata in answers:
                    if rtype == "TXT" and hasattr(rdata, "strings") and rdata.strings:
                        vals.append(b"".join(rdata.strings).decode("utf-8", errors="replace"))
                    else:
                        vals.append(rdata.to_text().strip('"'))

                if rtype == "TXT":
                    txt_records.extend(vals)
                elif rtype == "NS":
                    ns_servers.extend(vals)

                await context.emit_finding(
                    Finding(
                        category=Category.DNS,
                        severity=Severity.INFO,
                        title=f"DNS {rtype} Record Discovered",
                        description=f"Domain {target.domain} publishes {len(vals)} {rtype} record(s): {', '.join(vals[:3])}{'...' if len(vals) > 3 else ''}",
                        target=target.domain,
                        source_module=self.name,
                        data={"record_type": rtype, "records": vals, "ttl": answers.ttl},
                    )
                )
            except dns.resolver.NXDOMAIN:
                if rtype == "A":
                    await context.emit_finding(
                        Finding(
                            category=Category.DNS,
                            severity=Severity.MEDIUM,
                            title="Domain Resolves to NXDOMAIN (Non-Existent Domain)",
                            description=f"Apex domain {target.domain} returned NXDOMAIN. Domain does not have active DNS records.",
                            target=target.domain,
                            source_module=self.name,
                            data={"record_type": "A", "status": "NXDOMAIN"},
                            remediation="Verify domain registration and active DNS delegation.",
                        )
                    )
            except dns.resolver.NoAnswer:
                if rtype == "CAA":
                    await context.emit_finding(
                        Finding(
                            category=Category.DNS,
                            severity=Severity.LOW,
                            title="Missing CAA (Certificate Authority Authorization) Record",
                            description="Domain does not specify CAA records. Any public CA can issue certificates for this domain.",
                            target=target.domain,
                            source_module=self.name,
                            data={"record_type": "CAA", "missing": True},
                            remediation="Add DNS CAA records specifying approved Certificate Authorities (e.g. '0 issue \"letsencrypt.org\"').",
                        )
                    )
            except Exception as e:
                await context.log("warning", f"[DNS] Could not query {rtype}: {e}")

        # 2. SPF Evaluation
        if context.cancelled:
            return
        current_step += 1
        await context.update_progress(self.name, current_step / total_steps, "Auditing SPF defenses...")
        spf_records = [txt for txt in txt_records if txt.startswith("v=spf1")]

        if len(spf_records) > 1:
            await context.emit_finding(
                Finding(
                    category=Category.DNS,
                    severity=Severity.HIGH,
                    title="Multiple SPF Records Published (RFC 7208 Violation)",
                    description=(
                        f"Domain publishes {len(spf_records)} separate SPF records. According to RFC 7208 Section 3.2, "
                        "publishing multiple SPF records causes mail receivers to return a PermError, failing email authentication."
                    ),
                    target=target.domain,
                    source_module=self.name,
                    data={"spf_records": spf_records},
                    remediation="Merge all authorized senders into a single consolidated 'v=spf1 ...' TXT record.",
                )
            )
        elif len(spf_records) == 1:
            txt = spf_records[0]
            if "+all" in txt:
                await context.emit_finding(
                    Finding(
                        category=Category.DNS,
                        severity=Severity.HIGH,
                        title="Insecure SPF Record Configuration (+all)",
                        description=f"SPF record contains '+all', explicitly permitting any IP address in the world to send mail on behalf of {target.domain}.",
                        target=target.domain,
                        source_module=self.name,
                        data={"spf_record": txt},
                        remediation="Change '+all' to '-all' (hard fail) or '~all' (soft fail) to prevent unauthorized email spoofing.",
                    )
                )
            elif "?all" in txt:
                await context.emit_finding(
                    Finding(
                        category=Category.DNS,
                        severity=Severity.LOW,
                        title="Permissive SPF Policy (?all Neutral)",
                        description=f"SPF record ends with '?all' (neutral policy). Receivers will not fail or reject spoofed emails.",
                        target=target.domain,
                        source_module=self.name,
                        data={"spf_record": txt},
                        remediation="Upgrade '?all' to '~all' (softfail) or '-all' (hardfail) once all outbound mail sources are enumerated.",
                    )
                )
            else:
                await context.emit_finding(
                    Finding(
                        category=Category.DNS,
                        severity=Severity.INFO,
                        title="Valid SPF Email Record Configured",
                        description=f"Domain enforces SPF restrictions: {txt}",
                        target=target.domain,
                        source_module=self.name,
                        data={"spf_record": txt},
                    )
                )
        else:
            await context.emit_finding(
                Finding(
                    category=Category.DNS,
                    severity=Severity.MEDIUM,
                    title="Missing SPF Record",
                    description=f"No SPF (v=spf1) record discovered for {target.domain}. Domain is susceptible to email spoofing.",
                    target=target.domain,
                    source_module=self.name,
                    data={"missing_spf": True},
                    remediation="Publish a TXT record with v=spf1 specifying authorized outbound mail servers.",
                )
            )

        # 3. DMARC Evaluation
        if context.cancelled:
            return
        current_step += 1
        await context.update_progress(self.name, current_step / total_steps, "Auditing DMARC policy...")
        dmarc_domain = f"_dmarc.{target.domain}"
        try:
            dmarc_answers = await resolver.resolve(dmarc_domain, "TXT")
            dmarc_texts = []
            for rdata in dmarc_answers:
                if hasattr(rdata, "strings") and rdata.strings:
                    dmarc_texts.append(b"".join(rdata.strings).decode("utf-8", errors="replace"))
                else:
                    dmarc_texts.append(rdata.to_text().strip('"'))

            dmarc_policy = None
            for txt in dmarc_texts:
                if txt.startswith("v=DMARC1"):
                    dmarc_policy = txt
                    break

            if dmarc_policy:
                if "p=none" in dmarc_policy:
                    await context.emit_finding(
                        Finding(
                            category=Category.DNS,
                            severity=Severity.LOW,
                            title="Permissive DMARC Policy (p=none)",
                            description="DMARC record exists but policy is set to 'p=none' (reporting only, no rejection/quarantine of spoofed emails).",
                            target=dmarc_domain,
                            source_module=self.name,
                            data={"dmarc_record": dmarc_policy},
                            remediation="Upgrade DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject' once mail sources are verified.",
                        )
                    )
                else:
                    has_rua = "rua=" in dmarc_policy.lower()
                    if not has_rua:
                        await context.emit_finding(
                            Finding(
                                category=Category.DNS,
                                severity=Severity.LOW,
                                title="DMARC Policy Configured Without Reporting URI (Missing rua)",
                                description="DMARC policy is active but lacks 'rua=mailto:...' aggregate reporting, preventing feedback on deliverability issues.",
                                target=dmarc_domain,
                                source_module=self.name,
                                data={"dmarc_record": dmarc_policy},
                                remediation="Add 'rua=mailto:dmarc-reports@example.com' to receive aggregate forensic feedback.",
                            )
                        )
                    else:
                        await context.emit_finding(
                            Finding(
                                category=Category.DNS,
                                severity=Severity.INFO,
                                title="Enforced DMARC Policy Active",
                                description=f"Domain has an active protective DMARC policy: {dmarc_policy}",
                                target=dmarc_domain,
                                source_module=self.name,
                                data={"dmarc_record": dmarc_policy},
                            )
                        )
            else:
                await context.emit_finding(
                    Finding(
                        category=Category.DNS,
                        severity=Severity.MEDIUM,
                        title="Missing DMARC Policy",
                        description=f"No DMARC policy record found at {dmarc_domain}.",
                        target=dmarc_domain,
                        source_module=self.name,
                        data={"missing_dmarc": True},
                        remediation=f"Configure a DMARC TXT record at {dmarc_domain} (e.g. 'v=DMARC1; p=quarantine; rua=mailto:dmarc@{target.domain}').",
                    )
                )
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            await context.emit_finding(
                Finding(
                    category=Category.DNS,
                    severity=Severity.MEDIUM,
                    title="Missing DMARC Policy Record",
                    description=f"DNS lookup for {dmarc_domain} returned no records. Domain is vulnerable to phishing impersonation.",
                    target=dmarc_domain,
                    source_module=self.name,
                    data={"missing_dmarc": True},
                    remediation=f"Publish a DMARC TXT record at {dmarc_domain}.",
                )
            )
        except Exception as e:
            await context.log("warning", f"[DNS] DMARC check failed: {e}")

        # 4. Authoritative Nameserver & AXFR (Zone Transfer) Security Check
        if ns_servers and not context.cancelled:
            current_step += 1
            await context.update_progress(self.name, current_step / total_steps, "Testing DNS zone transfer security...")
            clean_ns = [ns.rstrip(".") for ns in ns_servers]
            for ns_host in clean_ns[:3]:
                if context.cancelled:
                    break
                try:
                    ns_ips = await resolver.resolve(ns_host, "A")
                    for ns_ip_rdata in ns_ips:
                        ns_ip = ns_ip_rdata.to_text()
                        loop = asyncio.get_running_loop()

                        def try_axfr(ip=ns_ip, domain=target.domain):
                            try:
                                z = dns.zone.from_xfr(dns.query.xfr(ip, domain, timeout=2.0, lifetime=2.0))
                                return list(z.nodes.keys())
                            except Exception:
                                return None

                        nodes = await loop.run_in_executor(None, try_axfr)
                        if nodes:
                            await context.emit_finding(
                                Finding(
                                    category=Category.DNS,
                                    severity=Severity.CRITICAL,
                                    title=f"Critical: DNS Zone Transfer (AXFR) Allowed by {ns_host}",
                                    description=(
                                        f"Authoritative nameserver {ns_host} ({ns_ip}) permitted full DNS zone transfer (AXFR) "
                                        f"for {target.domain}, exposing {len(nodes)} internal DNS records and hostnames."
                                    ),
                                    target=f"{ns_host}:{ns_ip}",
                                    source_module=self.name,
                                    data={"nameserver": ns_host, "ip": ns_ip, "exposed_nodes_count": len(nodes)},
                                    remediation="Disable unrestricted zone transfers (AXFR) on authoritative nameservers.",
                                )
                            )
                            break
                except Exception:
                    pass

        # 4. Active Subdomain Probing (in Standard / Deep modes)
        if target.depth in [InvestigationDepth.STANDARD, InvestigationDepth.DEEP]:
            sub_prefixes = COMMON_PREFIXES if target.depth == InvestigationDepth.STANDARD else COMMON_PREFIXES + [
                "staging-api", "uat", "jenkins", "gitlab", "grafana", "k8s", "vpn2", "backup", "db", "intranet", "demo"
            ]
            await context.log("info", f"[DNS] Probing {len(sub_prefixes)} common subdomain prefixes")

            async def probe_subdomain(prefix: str):
                if context.cancelled:
                    return
                fqdn = f"{prefix}.{target.domain}"
                try:
                    ans = await resolver.resolve(fqdn, "A")
                    ips = [rdata.to_text() for rdata in ans]
                    await context.emit_finding(
                        Finding(
                            category=Category.DNS,
                            severity=Severity.INFO,
                            title=f"Active Subdomain Discovered: {fqdn}",
                            description=f"Subdomain {fqdn} resolves to: {', '.join(ips)}",
                            target=fqdn,
                            source_module=self.name,
                            data={"subdomain": fqdn, "ips": ips, "ttl": ans.ttl},
                        )
                    )
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                    pass
                except Exception:
                    pass

            # Probe with semaphore to avoid overwhelming resolver
            sem = asyncio.Semaphore(10)

            async def bounded_probe(prefix: str):
                async with sem:
                    await probe_subdomain(prefix)

            await asyncio.gather(*(bounded_probe(p) for p in sub_prefixes))

        await context.update_progress(self.name, 1.0, "DNS audit completed")
        await context.log("info", f"[DNS] Completed DNS audit for {target.domain}")
