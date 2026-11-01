"""
Due Diligence & Client Risk Auditor for Sherlock OSINT Suite.
Supports both Person and Business investigation modes using publicly available
records, sanctions/PEP screening, corporate registers, phone line-type audits,
disposable email detection, and contact consistency analysis.
"""

from __future__ import annotations

import re
import difflib
from typing import Any, Dict, List, Optional
import httpx
import dns.asyncresolver
import phonenumbers
from phonenumbers import PhoneNumberType

from .base import BaseModule
from ..context import InvestigationContext
from ..models import Category, ClientProfile, ClientType, Finding, Severity, Target


DISPOSABLE_EMAIL_DOMAINS = {
    "10minutemail.com",
    "dispostable.com",
    "fakemailgenerator.com",
    "fakeinbox.com",
    "getairmail.com",
    "generator.email",
    "guerrillamail.biz",
    "guerrillamail.com",
    "guerrillamail.de",
    "guerrillamail.net",
    "guerrillamail.org",
    "inboxkitten.com",
    "mailinator.com",
    "mohmal.com",
    "nada.ltd",
    "sharklasers.com",
    "temp-mail.org",
    "tempmail.com",
    "tempmail.net",
    "throwawaymail.com",
    "trashmail.com",
    "yopmail.com",
    "yopmail.fr",
    "yopmail.net",
}

FREEMAIL_DOMAINS = {
    "aol.com",
    "gmail.com",
    "gmx.com",
    "gmx.de",
    "hotmail.co.uk",
    "hotmail.com",
    "icloud.com",
    "live.com",
    "mail.com",
    "msn.com",
    "outlook.com",
    "proton.me",
    "protonmail.com",
    "yahoo.co.uk",
    "yahoo.com",
    "zoho.com",
}

KNOWN_FINANCIAL_BRANDS = [
    "paypal",
    "stripe",
    "apple",
    "microsoft",
    "google",
    "amazon",
    "chase",
    "wellsfargo",
    "bankofamerica",
    "binance",
    "coinbase",
]

CMRA_PATTERNS = [
    r"\bp\.?o\.?\s*box\b",
    r"\bpost\s*office\s*box\b",
    r"\bpmb\s*#?\d+\b",
    r"\bups\s*store\b",
    r"\bregus\b",
    r"\bwework\b",
    r"\bvirtual\s*office\b",
    r"\bpostal\s*annex\b",
    r"\bdavinci\s*virtual\b",
    r"\bmailbox\s*(plus|etc|center)\b",
]


class DueDiligenceModule(BaseModule):
    module_id = "due_diligence"
    name = "Due Diligence & Client Risk Auditor"
    description = (
        "Audits prospective clients and vendors with Person & Business modes: "
        "sanctions/PEP screening, corporate registries, VOIP phone risk, email hygiene, and office CMRA detection."
    )
    category = Category.DUE_DILIGENCE
    default_enabled = True

    async def run(self, target: Target, context: InvestigationContext) -> None:
        profile = target.client_profile
        if not profile:
            # Build implicit profile from Target domain and organization
            profile = ClientProfile(
                client_type=ClientType.BUSINESS,
                domain=target.domain if target.domain != "due-diligence.local" else None,
                company=target.organization,
            )

        mode_name = profile.client_type.value.upper()
        await context.log(
            "info",
            f"[Due Diligence] Initiating {mode_name} audit (Subject: {profile.name or profile.company or target.domain})",
        )

        # 1. Phone number analysis
        if profile.phone:
            await self._audit_phone(profile.phone, profile, target, context)

        # 2. Email hygiene and deliverability
        if profile.email:
            await self._audit_email(profile.email, profile, target, context)

        # 3. Address & CMRA check
        if profile.address:
            await self._audit_address(profile.address, profile, target, context)

        # 4. Mode-specific investigation
        if profile.client_type == ClientType.PERSON:
            await self._audit_person_mode(profile, target, context)
        else:
            await self._audit_business_mode(profile, target, context)

        # 5. Cross-field consistency
        await self._audit_consistency(profile, target, context)

        await context.log("info", f"[Due Diligence] Completed {mode_name} audit.")

    async def _audit_phone(
        self,
        phone_raw: str,
        profile: ClientProfile,
        target: Target,
        context: InvestigationContext,
    ) -> None:
        try:
            parsed = phonenumbers.parse(phone_raw, None if phone_raw.startswith("+") else "US")
        except phonenumbers.NumberParseException as e:
            await context.emit_finding(
                Finding(
                    category=Category.DUE_DILIGENCE,
                    severity=Severity.HIGH,
                    title="Malformed / Unparseable Phone Number",
                    description=f"Supplied phone number '{phone_raw}' failed standard E.164 parsing: {e}",
                    target=target.domain,
                    source_module=self.module_id,
                    data={"raw_phone": phone_raw, "error": str(e)},
                    remediation="Request client provide an active, international standard phone number with country code.",
                )
            )
            return

        if not phonenumbers.is_valid_number(parsed):
            await context.emit_finding(
                Finding(
                    category=Category.DUE_DILIGENCE,
                    severity=Severity.HIGH,
                    title="Invalid Phone Number Format",
                    description=f"Phone number '{phone_raw}' is structurally invalid or unallocated under country plan +{parsed.country_code}.",
                    target=target.domain,
                    source_module=self.module_id,
                    data={"raw_phone": phone_raw, "country_code": parsed.country_code},
                    remediation="Verify phone number accuracy with client; invalid numbers indicate potential fabrication.",
                )
            )
            return

        ntype = phonenumbers.number_type(parsed)
        region = phonenumbers.region_code_for_number(parsed) or "Unknown"
        intl_fmt = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)

        type_names = {
            PhoneNumberType.FIXED_LINE: "fixed_line",
            PhoneNumberType.MOBILE: "mobile",
            PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_line_or_mobile",
            PhoneNumberType.TOLL_FREE: "toll_free",
            PhoneNumberType.PREMIUM_RATE: "premium_rate",
            PhoneNumberType.SHARED_COST: "shared_cost",
            PhoneNumberType.VOIP: "voip",
            PhoneNumberType.PERSONAL_NUMBER: "personal_number",
            PhoneNumberType.PAGER: "pager",
            PhoneNumberType.UAN: "uan",
            PhoneNumberType.VOICEMAIL: "voicemail",
        }
        line_name = type_names.get(ntype, "unknown")

        if ntype == PhoneNumberType.VOIP:
            await context.emit_finding(
                Finding(
                    category=Category.DUE_DILIGENCE,
                    severity=Severity.HIGH,
                    title="Virtual VOIP Phone Number Detected",
                    description=(
                        f"Phone number {intl_fmt} resolves to a Virtual VOIP service (e.g. Twilio, Google Voice, Bandwidth). "
                        "VOIP lines can be provisioned instantly and anonymously, posing elevated risk for impersonation and fraud."
                    ),
                    target=target.domain,
                    source_module=self.module_id,
                    data={"formatted": intl_fmt, "region": region, "line_type": "VOIP"},
                    remediation="Require secondary identity verification or an authenticated enterprise landline/mobile direct contact.",
                )
            )
        elif ntype in (PhoneNumberType.MOBILE, PhoneNumberType.FIXED_LINE, PhoneNumberType.FIXED_LINE_OR_MOBILE):
            await context.emit_finding(
                Finding(
                    category=Category.DUE_DILIGENCE,
                    severity=Severity.INFO,
                    title="Verified Telecom Carrier Line Type",
                    description=f"Phone number {intl_fmt} is an allocated {line_name} line in jurisdiction '{region}'.",
                    target=target.domain,
                    source_module=self.module_id,
                    data={"formatted": intl_fmt, "region": region, "line_type": line_name},
                )
            )
        else:
            await context.emit_finding(
                Finding(
                    category=Category.DUE_DILIGENCE,
                    severity=Severity.LOW,
                    title=f"Special Phone Number Line Type: {line_name.upper()}",
                    description=f"Phone number {intl_fmt} is categorized as {line_name} in region '{region}'.",
                    target=target.domain,
                    source_module=self.module_id,
                    data={"formatted": intl_fmt, "region": region, "line_type": line_name},
                )
            )

    async def _audit_email(
        self,
        email: str,
        profile: ClientProfile,
        target: Target,
        context: InvestigationContext,
    ) -> None:
        email = email.strip().lower()
        if "@" not in email:
            await context.emit_finding(
                Finding(
                    category=Category.DUE_DILIGENCE,
                    severity=Severity.HIGH,
                    title="Malformed Email Address",
                    description=f"Client email '{email}' is missing the domain separator '@'.",
                    target=target.domain,
                    source_module=self.module_id,
                    data={"email": email},
                )
            )
            return

        mailbox, domain = email.split("@", 1)
        domain = domain.strip().rstrip(".")

        # Disposable email check
        if domain in DISPOSABLE_EMAIL_DOMAINS:
            await context.emit_finding(
                Finding(
                    category=Category.DUE_DILIGENCE,
                    severity=Severity.CRITICAL,
                    title="Disposable / Burner Email Service Detected",
                    description=(
                        f"Client email domain '@{domain}' is a recognized temporary throwaway/burner email inbox service. "
                        "Communications to this address offer zero legal accountability and will expire."
                    ),
                    target=target.domain,
                    source_module=self.module_id,
                    data={"email": email, "domain": domain, "disposable": True},
                    remediation="Reject engagement using disposable mail. Require verifiable business or authenticated personal email.",
                )
            )
            return

        # Freemail check
        if domain in FREEMAIL_DOMAINS:
            if profile.client_type == ClientType.BUSINESS:
                await context.emit_finding(
                    Finding(
                        category=Category.DUE_DILIGENCE,
                        severity=Severity.MEDIUM,
                        title="Generic Freemail Used for Corporate Engagement",
                        description=(
                            f"Representative provided consumer webmail '@{domain}' instead of a company-owned domain. "
                            "Commercial negotiations conducted over free webmail have high exposure to Business Email Compromise (BEC)."
                        ),
                        target=target.domain,
                        source_module=self.module_id,
                        data={"email": email, "domain": domain},
                        remediation="Request corporate communications be sent from an authenticated enterprise domain under the company's control.",
                    )
                )
            else:
                await context.emit_finding(
                    Finding(
                        category=Category.DUE_DILIGENCE,
                        severity=Severity.INFO,
                        title="Standard Consumer Webmail Provider",
                        description=f"Individual contact email uses common provider '@{domain}'.",
                        target=target.domain,
                        source_module=self.module_id,
                        data={"email": email, "domain": domain},
                    )
                )

        # MX DNS validation
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 5.0
        try:
            mx_answers = await resolver.resolve(domain, "MX")
            hosts = [str(r.exchange).rstrip(".") for r in mx_answers]
            await context.emit_finding(
                Finding(
                    category=Category.DUE_DILIGENCE,
                    severity=Severity.INFO,
                    title="Email Domain Mail Exchangers (MX) Verified",
                    description=f"Domain '@{domain}' publishes active MX routing through: {', '.join(hosts[:3])}.",
                    target=target.domain,
                    source_module=self.module_id,
                    data={"domain": domain, "mx_records": hosts},
                )
            )
        except Exception as e:
            await context.emit_finding(
                Finding(
                    category=Category.DUE_DILIGENCE,
                    severity=Severity.HIGH,
                    title="Email Domain Has No Functional MX Records",
                    description=f"Domain '@{domain}' failed MX resolution ({e}). Inbound emails to this address will bounce.",
                    target=target.domain,
                    source_module=self.module_id,
                    data={"domain": domain, "error": str(e)},
                    remediation="Verify email spelling; domain cannot receive incoming correspondence.",
                )
            )

    async def _audit_address(
        self,
        address: str,
        profile: ClientProfile,
        target: Target,
        context: InvestigationContext,
    ) -> None:
        addr_lower = address.lower()
        matched_patterns = []
        for pat in CMRA_PATTERNS:
            if re.search(pat, addr_lower):
                matched_patterns.append(pat)

        if matched_patterns:
            sev = Severity.MEDIUM if profile.client_type == ClientType.BUSINESS else Severity.LOW
            await context.emit_finding(
                Finding(
                    category=Category.DUE_DILIGENCE,
                    severity=sev,
                    title="Commercial Mail Receiving Agency (CMRA) / Virtual Office Detected",
                    description=(
                        f"Address '{address}' contains mail-drop / virtual office indicators (matched: {len(matched_patterns)} pattern(s)). "
                        "Entity may not maintain a physical operational presence at this location."
                    ),
                    target=target.domain,
                    source_module=self.module_id,
                    data={"address": address, "matched_patterns": matched_patterns},
                    remediation="Request proof of operational physical location or verify corporate state registry filing.",
                )
            )

    async def _audit_person_mode(
        self,
        profile: ClientProfile,
        target: Target,
        context: InvestigationContext,
    ) -> None:
        if not profile.name:
            await context.log("warn", "[Due Diligence] Person mode enabled but no person name provided.")
            return

        name = profile.name.strip()
        await context.log("info", f"[Due Diligence] Auditing public records & sanctions for: {name}")

        # 1. Sanctions & PEP Screening (OpenSanctions public search)
        await self._check_opensanctions(name, target, context)

        # 2. Corporate Officer / Directorship Registry (OpenCorporates public officers search)
        await self._check_opencorporates_officers(name, profile.company, target, context)

        # 3. Australian Business Register (ABR) & Trust / Trustee Detection
        await self._check_abr_trusts(name, profile.company, target, context)

        # 4. Australian Court Hearings & Adverse Media Screening
        await self._check_court_and_media(name, profile.company, target, context)

        # 5. Regulatory Verification Links
        await self._emit_registry_verification_reference(name, target, context)

    async def _check_opensanctions(
        self,
        name: str,
        target: Target,
        context: InvestigationContext,
    ) -> None:
        url = "https://api.opensanctions.org/search/default"
        headers = {"User-Agent": "Sherlock-DueDiligence/1.0"}
        params = {"q": name, "limit": "5"}

        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                resp = await client.get(url, params=params, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    results = data.get("results", [])
                    high_matches = []
                    for r in results:
                        score = r.get("score", 0.0)
                        schema = r.get("schema", "")
                        caption = r.get("caption", "")
                        if score >= 0.75:
                            high_matches.append(
                                {
                                    "caption": caption,
                                    "score": score,
                                    "schema": schema,
                                    "topics": r.get("properties", {}).get("topics", []),
                                }
                            )

                    if high_matches:
                        await context.emit_finding(
                            Finding(
                                category=Category.DUE_DILIGENCE,
                                severity=Severity.CRITICAL,
                                title="Global Sanctions / Watchlist Screening Alert",
                                description=(
                                    f"Subject name '{name}' returned {len(high_matches)} high-confidence match(es) "
                                    f"on international sanctions/PEP watchlists: {high_matches[0]['caption']} (Score: {high_matches[0]['score']})."
                                ),
                                target=target.domain,
                                source_module=self.module_id,
                                data={"query": name, "matches": high_matches},
                                remediation="Immediately freeze onboarding and escalate to legal/compliance counsel for formal identity verification.",
                            )
                        )
                    else:
                        await context.emit_finding(
                            Finding(
                                category=Category.DUE_DILIGENCE,
                                severity=Severity.INFO,
                                title="Sanctions & PEP Screening Clearance",
                                description=f"No high-confidence matches found on public international sanctions or PEP watchlists for '{name}'.",
                                target=target.domain,
                                source_module=self.module_id,
                                data={"query": name, "status": "CLEARED"},
                            )
                        )
                else:
                    await context.log("debug", f"OpenSanctions query returned status {resp.status_code}")
        except Exception as e:
            await context.log("debug", f"OpenSanctions request omitted (network/timeout): {e}")

    async def _check_opencorporates_officers(
        self,
        name: str,
        company: Optional[str],
        target: Target,
        context: InvestigationContext,
    ) -> None:
        url = "https://api.opencorporates.com/v0.4/officers/search"
        headers = {"User-Agent": "Sherlock-DueDiligence/1.0"}
        params = {"q": name, "per_page": "5"}

        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                resp = await client.get(url, params=params, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    officers = data.get("results", {}).get("officers", [])
                    if officers:
                        records = []
                        company_match = False
                        for entry in officers:
                            off = entry.get("officer", {})
                            corp_name = off.get("company", {}).get("name", "Unknown")
                            position = off.get("position", "Officer")
                            jurisdiction = off.get("jurisdiction_code", "")
                            records.append(
                                {
                                    "officer_name": off.get("name"),
                                    "company": corp_name,
                                    "position": position,
                                    "jurisdiction": jurisdiction,
                                }
                            )
                            if company and company.lower() in corp_name.lower():
                                company_match = True

                        if company_match:
                            await context.emit_finding(
                                Finding(
                                    category=Category.DUE_DILIGENCE,
                                    severity=Severity.INFO,
                                    title=f"Verified Corporate Officer Status for {company}",
                                    description=f"Public registers confirm '{name}' is recorded as an officer/principal for '{company}'.",
                                    target=target.domain,
                                    source_module=self.module_id,
                                    data={"name": name, "company": company, "records": records},
                                )
                            )
                        else:
                            await context.emit_finding(
                                Finding(
                                    category=Category.DUE_DILIGENCE,
                                    severity=Severity.INFO,
                                    title="Public Corporate Directorships & Officer Records Found",
                                    description=(
                                        f"Public corporate registries link '{name}' to {len(records)} formal corporate role(s) "
                                        f"(e.g. {records[0]['company']} - {records[0]['position']})."
                                    ),
                                    target=target.domain,
                                    source_module=self.module_id,
                                    data={"name": name, "records": records},
                                )
                            )
        except Exception as e:
            await context.log("debug", f"OpenCorporates officer query omitted (network/timeout): {e}")

    async def _audit_business_mode(
        self,
        profile: ClientProfile,
        target: Target,
        context: InvestigationContext,
    ) -> None:
        company = profile.company or profile.name
        domain = profile.domain or (target.domain if target.domain != "due-diligence.local" else None)

        if not company and not domain:
            await context.log("warn", "[Due Diligence] Business mode enabled but no company name or domain specified.")
            return

        # 1. Lookalike & Typosquatting Brand Impersonation check
        if domain:
            domain_stem = domain.split(".")[0].lower()
            for brand in KNOWN_FINANCIAL_BRANDS:
                if domain_stem != brand:
                    ratio = difflib.SequenceMatcher(None, domain_stem, brand).ratio()
                    if ratio >= 0.80 or (brand in domain_stem and len(domain_stem) <= len(brand) + 5):
                        await context.emit_finding(
                            Finding(
                                category=Category.DUE_DILIGENCE,
                                severity=Severity.CRITICAL,
                                title=f"High Brand Impersonation / Typosquatting Risk ({brand.capitalize()})",
                                description=(
                                    f"Domain '{domain}' exhibits high similarity ({round(ratio*100)}%) to protected brand '{brand.capitalize()}'. "
                                    "Potential brand spoofing, credential harvesting, or fraudulent representation."
                                ),
                                target=target.domain,
                                source_module=self.module_id,
                                data={"domain": domain, "brand": brand, "similarity": round(ratio, 2)},
                                remediation="Verify domain ownership through official executive channels. Extreme caution required.",
                            )
                        )
                        break

        # 2. OpenCorporates Company Search
        if company:
            await self._check_opencorporates_company(company, target, context)
            await self._check_abr_trusts(company, None, target, context)
            await self._check_court_and_media(company, None, target, context)
            await self._emit_registry_verification_reference(company, target, context)

    async def _check_opencorporates_company(
        self,
        company: str,
        target: Target,
        context: InvestigationContext,
    ) -> None:
        url = "https://api.opencorporates.com/v0.4/companies/search"
        headers = {"User-Agent": "Sherlock-DueDiligence/1.0"}
        params = {"q": company, "per_page": "5"}

        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                resp = await client.get(url, params=params, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    comps = data.get("results", {}).get("companies", [])
                    if comps:
                        top = comps[0].get("company", {})
                        c_name = top.get("name", company)
                        status = (top.get("current_status") or "Active").lower()
                        jurisdiction = top.get("jurisdiction_code", "")
                        inc_date = top.get("incorporation_date", "")

                        if "dissolved" in status or "inactive" in status or "forfeited" in status:
                            await context.emit_finding(
                                Finding(
                                    category=Category.DUE_DILIGENCE,
                                    severity=Severity.HIGH,
                                    title="Corporate Registration Inactive or Dissolved",
                                    description=f"Public entity '{c_name}' in jurisdiction '{jurisdiction}' is recorded as: {status.upper()}.",
                                    target=target.domain,
                                    source_module=self.module_id,
                                    data={"company": c_name, "status": status, "jurisdiction": jurisdiction},
                                    remediation="Client may be operating under an inactive legal shell. Require proof of Good Standing.",
                                )
                            )
                        else:
                            await context.emit_finding(
                                Finding(
                                    category=Category.DUE_DILIGENCE,
                                    severity=Severity.INFO,
                                    title="Active Corporate Registration Verified",
                                    description=(
                                        f"Entity '{c_name}' confirmed active in jurisdiction '{jurisdiction}' "
                                        f"(Incorporated: {inc_date or 'Registered'})."
                                    ),
                                    target=target.domain,
                                    source_module=self.module_id,
                                    data={
                                        "company": c_name,
                                        "status": status,
                                        "jurisdiction": jurisdiction,
                                        "incorporation_date": inc_date,
                                    },
                                )
                            )
                    else:
                        await context.emit_finding(
                            Finding(
                                category=Category.DUE_DILIGENCE,
                                severity=Severity.LOW,
                                title="No Exact Corporate Registry Match",
                                description=f"Company name '{company}' did not yield an immediate exact match in open commercial registers.",
                                target=target.domain,
                                source_module=self.module_id,
                                data={"query": company},
                                remediation="Request formal registration number (EIN, CRN, or certificate of incorporation).",
                            )
                        )
        except Exception as e:
            await context.log("debug", f"OpenCorporates company search omitted (network/timeout): {e}")

    async def _audit_consistency(
        self,
        profile: ClientProfile,
        target: Target,
        context: InvestigationContext,
    ) -> None:
        # Cross-field checks: e.g. Claimed company vs email domain
        if profile.company and profile.email and "@" in profile.email:
            domain = profile.email.split("@")[1].lower()
            if domain not in FREEMAIL_DOMAINS and domain not in DISPOSABLE_EMAIL_DOMAINS:
                stem = domain.split(".")[0]
                comp_cleaned = re.sub(r"[^a-z0-9]", "", profile.company.lower())
                stem_cleaned = re.sub(r"[^a-z0-9]", "", stem)
                if stem_cleaned and comp_cleaned:
                    ratio = difflib.SequenceMatcher(None, stem_cleaned, comp_cleaned).ratio()
                    if ratio < 0.35 and comp_cleaned not in stem_cleaned and stem_cleaned not in comp_cleaned:
                        await context.emit_finding(
                            Finding(
                                category=Category.DUE_DILIGENCE,
                                severity=Severity.MEDIUM,
                                title="Claimed Company and Email Domain Discrepancy",
                                description=(
                                    f"Contact email domain '@{domain}' has low coherence with claimed entity name '{profile.company}'. "
                                    "Ensure representative is an authorized agent of the stated organization."
                                ),
                                target=target.domain,
                                source_module=self.module_id,
                                data={"company": profile.company, "email_domain": domain, "similarity": round(ratio, 2)},
                                remediation="Verify authorization letter or require email confirmation from primary corporate apex domain.",
                            )
                        )

    async def _check_abr_trusts(
        self,
        query: str,
        company: Optional[str],
        target: Target,
        context: InvestigationContext,
    ) -> None:
        url = "https://abr.business.gov.au/Search/ResultsActive"
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        params = {"SearchText": query}
        try:
            async with httpx.AsyncClient(timeout=7.0) as client:
                resp = await client.get(url, params=params, headers=headers, follow_redirects=True)
                if resp.status_code == 200:
                    rows = re.findall(r"<tr[^>]*>(.*?)</tr>", resp.text, re.DOTALL)
                    records = []
                    trust_records = []
                    for row in rows[1:]:
                        cols = [
                            re.sub(r"<[^>]+>", " ", c).strip()
                            for c in re.findall(r"<td[^>]*>(.*?)</td>", row, re.DOTALL)
                        ]
                        if len(cols) >= 3:
                            abn_col = " ".join(cols[0].split())
                            name_col = " ".join(cols[1].split())
                            type_col = " ".join(cols[2].split())
                            loc_col = " ".join(cols[3].split()) if len(cols) > 3 else ""
                            item = {
                                "abn": abn_col,
                                "name": name_col,
                                "type": type_col,
                                "location": loc_col,
                            }
                            records.append(item)
                            combined_text = (name_col + " " + type_col).lower()
                            if "trust" in combined_text or "trustee" in combined_text or "discretionary" in combined_text:
                                trust_records.append(item)

                    if trust_records:
                        top = trust_records[0]
                        await context.emit_finding(
                            Finding(
                                category=Category.DUE_DILIGENCE,
                                severity=Severity.INFO,
                                title="Australian Trust / Trustee Registration Identified (ABR)",
                                description=(
                                    f"Australian Business Register (ABR) matches '{query}' as associated with a registered Trust structure: "
                                    f"'{top['name']}' ({top['type']}) | ABN: {top['abn']} ({top['location']})."
                                ),
                                target=target.domain,
                                source_module=self.module_id,
                                data={"query": query, "trust_records": trust_records[:5], "total": len(trust_records)},
                            )
                        )
                    elif records:
                        top = records[0]
                        await context.emit_finding(
                            Finding(
                                category=Category.DUE_DILIGENCE,
                                severity=Severity.INFO,
                                title="Active Australian Business Register (ABR) Entity Found",
                                description=(
                                    f"Found {len(records)} active Australian registration(s) for '{query}'. "
                                    f"Primary: '{top['name']}' ({top['type']}) | ABN: {top['abn']} ({top['location']})."
                                ),
                                target=target.domain,
                                source_module=self.module_id,
                                data={"query": query, "records": records[:5], "total": len(records)},
                            )
                        )
        except Exception as e:
            await context.log("debug", f"ABR registry search omitted: {e}")

    async def _check_court_and_media(
        self,
        name: str,
        company: Optional[str],
        target: Target,
        context: InvestigationContext,
    ) -> None:
        import urllib.parse
        import xml.etree.ElementTree as ET

        search_term = f'"{name}"'
        if company:
            search_term += f' "{company}"'

        court_query = f"{search_term} (court OR hearing OR lawsuit OR charges OR ASIC OR sentenced OR tribunal)"
        url = f"https://news.google.com/rss/search?q={urllib.parse.quote(court_query)}&hl=en-AU&gl=AU&ceid=AU:en"
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        try:
            async with httpx.AsyncClient(timeout=7.0) as client:
                resp = await client.get(url, headers=headers, follow_redirects=True)
                if resp.status_code == 200:
                    root = ET.fromstring(resp.content)
                    items = root.findall(".//item")
                    articles = []
                    high_risk_articles = []

                    name_parts = [p.lower() for p in name.split() if len(p) > 2]

                    for it in items[:15]:
                        t_elem = it.find("title")
                        l_elem = it.find("link")
                        d_elem = it.find("pubDate")
                        if t_elem is not None and t_elem.text:
                            title = t_elem.text
                            title_lower = title.lower()
                            if all(p in title_lower for p in name_parts):
                                art = {
                                    "title": title,
                                    "link": l_elem.text if l_elem is not None else "",
                                    "date": d_elem.text if d_elem is not None else "",
                                }
                                articles.append(art)
                                if any(
                                    w in title_lower
                                    for w in ["fraud", "guilty", "scam", "jail", "convicted", "pleads", "asic ban", "banned"]
                                ):
                                    high_risk_articles.append(art)

                    if high_risk_articles:
                        top = high_risk_articles[0]
                        await context.emit_finding(
                            Finding(
                                category=Category.DUE_DILIGENCE,
                                severity=Severity.HIGH,
                                title="Adverse Court / Legal Enforcement Coverage Detected",
                                description=(
                                    f"Public media records {len(high_risk_articles)} adverse court/enforcement item(s) matching '{name}': "
                                    f"'{top['title']}' ({top['date']})."
                                ),
                                target=target.domain,
                                source_module=self.module_id,
                                data={"query": name, "articles": high_risk_articles},
                                remediation="Review primary court transcripts and regulatory records to confirm identity matching and status.",
                            )
                        )
                    elif articles:
                        top = articles[0]
                        await context.emit_finding(
                            Finding(
                                category=Category.DUE_DILIGENCE,
                                severity=Severity.MEDIUM,
                                title="Public Court Mentions & Legal News Identified",
                                description=(
                                    f"Found {len(articles)} legal/court news reference(s) mentioning '{name}': "
                                    f"'{top['title']}' ({top['date']})."
                                ),
                                target=target.domain,
                                source_module=self.module_id,
                                data={"query": name, "articles": articles},
                                remediation="Verify whether the subject is a party, witness, or legal representative.",
                            )
                        )
        except Exception as e:
            await context.log("debug", f"Court & news media query omitted: {e}")

    async def _emit_registry_verification_reference(
        self,
        name: str,
        target: Target,
        context: InvestigationContext,
    ) -> None:
        import urllib.parse

        encoded_name = urllib.parse.quote(name)
        austlii_url = f"https://www.austlii.edu.au/cgi-bin/sinosrch.cgi?query={encoded_name}"
        abr_url = f"https://abr.business.gov.au/Search/ResultsActive?SearchText={encoded_name}"

        await context.emit_finding(
            Finding(
                category=Category.DUE_DILIGENCE,
                severity=Severity.INFO,
                title="Authoritative Australian Backstory Verification Registers",
                description=(
                    f"Direct verification portals for '{name}':\n"
                    f"• AustLII Court Judgments: {austlii_url}\n"
                    f"• ABR Business / Trust Lookup: {abr_url}\n"
                    f"• ASIC Banned & Disqualified Register: https://asic.gov.au/online-services/search-asic-registers/banned-and-disqualified/\n"
                    f"• AFSA Bankruptcy Register (NPII): https://www.afsa.gov.au/bankruptcy/bankruptcy-register-search\n"
                    f"• Commonwealth Courts Portal: https://www.comcourts.gov.au/"
                ),
                target=target.domain,
                source_module=self.module_id,
                data={
                    "name": name,
                    "austlii_url": austlii_url,
                    "abr_url": abr_url,
                    "asic_banned_url": "https://asic.gov.au/online-services/search-asic-registers/banned-and-disqualified/",
                    "afsa_npii_url": "https://www.afsa.gov.au/bankruptcy/bankruptcy-register-search",
                },
            )
        )

