"""
RDAP (Registration Data Access Protocol) Domain Lifecycle & Registrar Auditor.
Audits domain registrar, nameservers, status flags, and warns about impending domain expiration.
"""

from __future__ import annotations

from datetime import datetime, timezone
import httpx
from ..context import InvestigationContext
from ..models import Category, Finding, Severity, Target
from .base import BaseModule


class RDAPScannerModule(BaseModule):
    module_id = "rdap_scanner"
    name = "RDAP Domain Lifecycle & Registrar"
    description = "Queries authoritative ICANN RDAP records for registration dates, registrar, and expiration status."
    category = Category.WHOIS_RDAP

    RDAP_BASE = "https://rdap.org/domain/"

    async def run(self, target: Target, context: InvestigationContext) -> None:
        await context.log("info", f"[RDAP] Querying domain registration metadata for {target.domain}")
        await context.update_progress(self.name, 0.2, "Querying RDAP registry...")

        timeout = httpx.Timeout(connect=5.0, read=target.timeout, write=5.0, pool=5.0)
        url = f"{self.RDAP_BASE}{target.domain}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Sherlock-OSINT-Suite/1.0",
            "Accept": "application/rdap+json, application/json",
        }

        data = None
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                else:
                    await context.log("warning", f"[RDAP] Service returned HTTP {resp.status_code}")
            except Exception as e:
                await context.log("warning", f"[RDAP] Query failed: {e}")

        if context.cancelled:
            return

        await context.update_progress(self.name, 0.7, "Analyzing registration status...")

        if not data:
            await context.emit_finding(
                Finding(
                    category=Category.WHOIS_RDAP,
                    severity=Severity.INFO,
                    title="RDAP Domain Records Unavailable",
                    description=f"Could not retrieve authoritative RDAP registry data for {target.domain}.",
                    target=target.domain,
                    source_module=self.name,
                    data={"domain": target.domain},
                )
            )
            await context.update_progress(self.name, 1.0, "RDAP complete")
            return

        # Extract Registrar
        registrar_name = "Unknown"
        for ent in data.get("entities", []):
            roles = ent.get("roles", [])
            if "registrar" in roles:
                vcard = ent.get("vcardArray", [])
                if len(vcard) > 1 and isinstance(vcard[1], list):
                    for item in vcard[1]:
                        if len(item) > 3 and item[0] == "fn":
                            registrar_name = str(item[3])
                            break

        # Extract Dates
        events = data.get("events", [])
        registration_date = None
        expiration_date = None

        for ev in events:
            action = str(ev.get("eventAction", "")).lower()
            date_str = ev.get("eventDate")
            if any(term in action for term in ["registration", "created"]) and date_str:
                registration_date = date_str
            elif any(term in action for term in ["expiration", "expire"]) and date_str:
                expiration_date = date_str

        # Calculate days until expiration
        days_until_exp = None
        now = datetime.now(timezone.utc)
        if expiration_date:
            try:
                exp_dt = datetime.fromisoformat(expiration_date.replace("Z", "+00:00"))
                days_until_exp = (exp_dt - now).days
            except Exception:
                pass

        status_codes = data.get("status", [])
        rdap_nameservers = [ns.get("ldhName") for ns in data.get("nameservers", []) if ns.get("ldhName")]

        # Check redemption / pending delete
        is_redemption = any("redemption" in s.lower() or "pendingdelete" in s.lower() for s in status_codes)
        if is_redemption:
            await context.emit_finding(
                Finding(
                    category=Category.WHOIS_RDAP,
                    severity=Severity.HIGH,
                    title="Domain in Redemption / Pending Deletion Status",
                    description=f"Domain status indicates redemption or pending deletion: {status_codes}. Domain may be dropped or auctioned.",
                    target=target.domain,
                    source_module=self.name,
                    data={"statuses": status_codes, "registrar": registrar_name},
                    remediation="Contact your registrar immediately to redeem the expired domain.",
                )
            )

        # Emit findings
        if days_until_exp is not None and days_until_exp < 30:
            sev = Severity.HIGH if days_until_exp < 7 else Severity.MEDIUM
            await context.emit_finding(
                Finding(
                    category=Category.WHOIS_RDAP,
                    severity=sev,
                    title=f"Imminent Domain Expiration: {days_until_exp} Days Remaining",
                    description=(
                        f"Domain {target.domain} will expire on {expiration_date} ({days_until_exp} days). "
                        "Unrenewed domains are vulnerable to immediate takeover or service outage."
                    ),
                    target=target.domain,
                    source_module=self.name,
                    data={
                        "registrar": registrar_name,
                        "expiration_date": expiration_date,
                        "days_remaining": days_until_exp,
                        "nameservers": rdap_nameservers,
                    },
                    remediation="Renew domain registration immediately with registrar.",
                )
            )
        else:
            await context.emit_finding(
                Finding(
                    category=Category.WHOIS_RDAP,
                    severity=Severity.INFO,
                    title=f"Domain Registration Verified (Registrar: {registrar_name})",
                    description=(
                        f"Registrar: {registrar_name}. Registered: {registration_date or 'N/A'}. "
                        f"Expires: {expiration_date or 'N/A'} "
                        f"({f'{days_until_exp} days remaining' if days_until_exp is not None else ''})."
                    ),
                    target=target.domain,
                    source_module=self.name,
                    data={
                        "registrar": registrar_name,
                        "registration_date": registration_date,
                        "expiration_date": expiration_date,
                        "days_remaining": days_until_exp,
                        "statuses": status_codes,
                        "nameservers": rdap_nameservers,
                    },
                )
            )

        # Check transfer lock status
        has_transfer_lock = any("transfer" in s.lower() and "prohibit" in s.lower() for s in status_codes)
        if not has_transfer_lock and status_codes:
            await context.emit_finding(
                Finding(
                    category=Category.WHOIS_RDAP,
                    severity=Severity.LOW,
                    title="Domain Missing Client/Server Transfer Lock",
                    description=(
                        f"No 'clientTransferProhibited' or 'serverTransferProhibited' status detected. "
                        "Domains without transfer locks are more vulnerable to unauthorized registrar transfers."
                    ),
                    target=target.domain,
                    source_module=self.name,
                    data={"statuses": status_codes},
                    remediation="Enable Registrar Lock (transfer lock) in your domain registrar control panel.",
                )
            )

        # Check DNSSEC status
        secure_dns = data.get("secureDNS", {})
        delegation_signed = secure_dns.get("delegationSigned")
        if delegation_signed is False:
            await context.emit_finding(
                Finding(
                    category=Category.WHOIS_RDAP,
                    severity=Severity.LOW,
                    title="Domain DNSSEC Delegation Unsigned",
                    description="Registrar RDAP records indicate DNSSEC is not signed in the root zone (delegationSigned: false).",
                    target=target.domain,
                    source_module=self.name,
                    data={"secure_dns": secure_dns},
                    remediation="Enable DNSSEC signing and publish DS records at your registrar.",
                )
            )

        await context.update_progress(self.name, 1.0, "RDAP audit complete")
        await context.log("info", f"[RDAP] Completed registration analysis for {target.domain}")
