"""
Web Security Headers & TLS Hygiene Auditor.
Checks HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and server technology leakage.
"""

from __future__ import annotations

import ssl
import httpx
from ..context import InvestigationContext
from ..models import Category, Finding, InvestigationDepth, Severity, Target
from .base import BaseModule


class HTTPHeadersScannerModule(BaseModule):
    module_id = "http_headers"
    name = "Web Security Headers & TLS Audit"
    description = "Inspects HTTP/HTTPS response headers for security controls, HSTS enforcement, and information leakage."
    category = Category.HTTP_HEADER

    async def run(self, target: Target, context: InvestigationContext) -> None:
        await context.log("info", f"[Headers] Starting HTTP security headers audit for {target.domain}")
        await context.update_progress(self.name, 0.1, "Probing HTTPS endpoint...")

        timeout = httpx.Timeout(connect=5.0, read=target.timeout, write=5.0, pool=5.0)
        headers_to_check = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Sherlock-OSINT-Suite/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        https_url = f"https://{target.domain}"
        http_url = f"http://{target.domain}"

        # 0. Test SSL/TLS certificate validity
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=True, follow_redirects=True) as verify_client:
                await verify_client.get(https_url, headers=headers_to_check)
        except (httpx.ConnectError, ssl.SSLError) as ssl_err:
            err_str = str(ssl_err)
            if any(term in err_str.lower() for term in ["certificate", "ssl", "cert", "verify"]):
                await context.emit_finding(
                    Finding(
                        category=Category.CERTIFICATE,
                        severity=Severity.HIGH,
                        title="Invalid or Untrusted TLS/SSL Certificate",
                        description=f"TLS connection to {https_url} failed certificate validation: {err_str}",
                        target=https_url,
                        source_module=self.name,
                        data={"url": https_url, "ssl_error": err_str},
                        remediation="Install a valid SSL/TLS certificate from a trusted CA matching the domain hostname.",
                    )
                )
        except Exception:
            pass

        async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
            # 1. Test HTTPS endpoint
            resp_https = None
            try:
                resp_https = await client.get(https_url, headers=headers_to_check)
            except Exception as e:
                await context.log("warning", f"[Headers] HTTPS connection error: {e}")

            if context.cancelled:
                return

            # 2. Test HTTP -> HTTPS redirection
            await context.update_progress(self.name, 0.3, "Testing HTTP to HTTPS redirection...")
            try:
                # Disallow automatic redirect to test the immediate response code
                async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=False) as no_redir_client:
                    resp_http = await no_redir_client.get(http_url, headers=headers_to_check)
                    location = resp_http.headers.get("location", "")
                    if resp_http.status_code in [301, 302, 307, 308] and location.startswith("https://"):
                        await context.emit_finding(
                            Finding(
                                category=Category.HTTP_HEADER,
                                severity=Severity.INFO,
                                title="HTTP to HTTPS Redirection Enforced",
                                description=f"Plain HTTP traffic redirects cleanly to HTTPS (HTTP {resp_http.status_code} -> {location}).",
                                target=http_url,
                                source_module=self.name,
                                data={"status_code": resp_http.status_code, "redirect_location": location},
                            )
                        )
                    else:
                        await context.emit_finding(
                            Finding(
                                category=Category.HTTP_HEADER,
                                severity=Severity.MEDIUM,
                                title="Missing Strict HTTP-to-HTTPS Redirection",
                                description=(
                                    f"Plain HTTP request returned status code {resp_http.status_code} without immediately "
                                    f"redirecting to HTTPS. Location: '{location or 'None'}'. Unencrypted traffic may be intercepted."
                                ),
                                target=http_url,
                                source_module=self.name,
                                data={"status_code": resp_http.status_code, "location": location},
                                remediation="Configure web server to issue an immediate HTTP 301 Permanent Redirect for all HTTP requests to HTTPS.",
                            )
                        )
            except Exception as e:
                await context.log("info", f"[Headers] HTTP port unreachable or timed out: {e}")

            if context.cancelled:
                return

            # 3. Security Header Analysis on HTTPS
            await context.update_progress(self.name, 0.6, "Analyzing security headers...")
            if not resp_https:
                await context.emit_finding(
                    Finding(
                        category=Category.HTTP_HEADER,
                        severity=Severity.MEDIUM,
                        title="HTTPS Endpoint Unreachable",
                        description=f"Could not establish HTTPS connection to {https_url}.",
                        target=https_url,
                        source_module=self.name,
                        data={"url": https_url},
                    )
                )
                await context.update_progress(self.name, 1.0, "Audit finished")
                return

            h = resp_https.headers

            # 3a. Strict-Transport-Security (HSTS)
            hsts = h.get("strict-transport-security")
            if not hsts:
                await context.emit_finding(
                    Finding(
                        category=Category.HTTP_HEADER,
                        severity=Severity.MEDIUM,
                        title="Missing Strict-Transport-Security (HSTS)",
                        description="HSTS header is missing. Browsers will not be forced to connect over HTTPS, leaving visitors vulnerable to SSL stripping.",
                        target=https_url,
                        source_module=self.name,
                        data={"header": "Strict-Transport-Security", "status": "missing"},
                        remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to response headers.",
                    )
                )
            else:
                is_subdomains = "includesubdomains" in hsts.lower()
                is_preload = "preload" in hsts.lower()
                await context.emit_finding(
                    Finding(
                        category=Category.HTTP_HEADER,
                        severity=Severity.INFO,
                        title="Strict-Transport-Security (HSTS) Configured",
                        description=f"HSTS header present: '{hsts}'. includeSubDomains: {is_subdomains}, preload: {is_preload}.",
                        target=https_url,
                        source_module=self.name,
                        data={"hsts": hsts, "includeSubDomains": is_subdomains, "preload": is_preload},
                    )
                )

            # 3b. Content-Security-Policy (CSP)
            csp = h.get("content-security-policy")
            if not csp:
                await context.emit_finding(
                    Finding(
                        category=Category.HTTP_HEADER,
                        severity=Severity.MEDIUM,
                        title="Missing Content-Security-Policy (CSP)",
                        description="No CSP header found. The application is missing a critical defense layer against Cross-Site Scripting (XSS) and data injection.",
                        target=https_url,
                        source_module=self.name,
                        data={"header": "Content-Security-Policy", "status": "missing"},
                        remediation="Define a restrictive Content-Security-Policy header restricting executable script sources and object embeds.",
                    )
                )
            else:
                weaknesses = []
                if "'unsafe-inline'" in csp:
                    weaknesses.append("'unsafe-inline'")
                if "'unsafe-eval'" in csp:
                    weaknesses.append("'unsafe-eval'")

                if weaknesses:
                    await context.emit_finding(
                        Finding(
                            category=Category.HTTP_HEADER,
                            severity=Severity.LOW,
                            title="Content-Security-Policy Weak Directives Allowed",
                            description=f"CSP contains permissive directive(s): {', '.join(weaknesses)}, reducing protection against XSS.",
                            target=https_url,
                            source_module=self.name,
                            data={"csp": csp, "weaknesses": weaknesses},
                            remediation="Refactor inline scripts to use cryptographic nonces or hashes instead of 'unsafe-inline'.",
                        )
                    )
                else:
                    await context.emit_finding(
                        Finding(
                            category=Category.HTTP_HEADER,
                            severity=Severity.INFO,
                            title="Content-Security-Policy (CSP) Active",
                            description=f"Valid CSP header enforced without obvious unsafe directives.",
                            target=https_url,
                            source_module=self.name,
                            data={"csp": csp},
                        )
                    )

            # 3c. X-Frame-Options (Clickjacking defense)
            xfo = h.get("x-frame-options")
            if not xfo and (not csp or "frame-ancestors" not in csp.lower()):
                await context.emit_finding(
                    Finding(
                        category=Category.HTTP_HEADER,
                        severity=Severity.LOW,
                        title="Missing X-Frame-Options Header",
                        description="Neither X-Frame-Options nor CSP frame-ancestors is present. Pages may be embedded in iframes on malicious sites (Clickjacking).",
                        target=https_url,
                        source_module=self.name,
                        data={"header": "X-Frame-Options", "status": "missing"},
                        remediation="Set 'X-Frame-Options: DENY' or 'SAMEORIGIN', or use CSP 'frame-ancestors'.",
                    )
                )
            elif xfo:
                await context.emit_finding(
                    Finding(
                        category=Category.HTTP_HEADER,
                        severity=Severity.INFO,
                        title=f"X-Frame-Options Configured ({xfo})",
                        description=f"Clickjacking protection enabled with policy: {xfo}",
                        target=https_url,
                        source_module=self.name,
                        data={"x_frame_options": xfo},
                    )
                )

            # 3d. X-Content-Type-Options
            xcto = h.get("x-content-type-options")
            if not xcto or xcto.lower() != "nosniff":
                await context.emit_finding(
                    Finding(
                        category=Category.HTTP_HEADER,
                        severity=Severity.LOW,
                        title="Missing X-Content-Type-Options: nosniff",
                        description="X-Content-Type-Options is missing or not set to 'nosniff'. Browsers may attempt MIME-sniffing, leading to unexpected script execution.",
                        target=https_url,
                        source_module=self.name,
                        data={"header": "X-Content-Type-Options", "value": xcto},
                        remediation="Add 'X-Content-Type-Options: nosniff' header.",
                    )
                )
            else:
                await context.emit_finding(
                    Finding(
                        category=Category.HTTP_HEADER,
                        severity=Severity.INFO,
                        title="X-Content-Type-Options: nosniff Active",
                        description="MIME-sniffing protection correctly enabled.",
                        target=https_url,
                        source_module=self.name,
                        data={"x_content_type_options": xcto},
                    )
                )

            # 3e. Referrer-Policy
            ref_pol = h.get("referrer-policy")
            if not ref_pol:
                await context.emit_finding(
                    Finding(
                        category=Category.HTTP_HEADER,
                        severity=Severity.LOW,
                        title="Missing Referrer-Policy Header",
                        description="No Referrer-Policy header specified. Browsers may leak path or query strings in HTTP Referer to external domains.",
                        target=https_url,
                        source_module=self.name,
                        data={"header": "Referrer-Policy", "status": "missing"},
                        remediation="Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
                    )
                )

            # 3f. Information Leakage (Server & X-Powered-By)
            server = h.get("server")
            if server:
                has_version = any(char.isdigit() for char in server)
                sev = Severity.LOW if has_version else Severity.INFO
                await context.emit_finding(
                    Finding(
                        category=Category.HTTP_HEADER,
                        severity=sev,
                        title=f"Server Technology Disclosed: {server}",
                        description=f"Server banner discloses web server software: '{server}'." + (" Contains explicit version numbers." if has_version else ""),
                        target=https_url,
                        source_module=self.name,
                        data={"server_header": server, "has_version": has_version},
                        remediation="Suppress or sanitize the 'Server' header in reverse proxy or web server configuration." if has_version else None,
                    )
                )

            x_powered_by = h.get("x-powered-by")
            if x_powered_by:
                await context.emit_finding(
                    Finding(
                        category=Category.HTTP_HEADER,
                        severity=Severity.LOW,
                        title=f"Backend Technology Disclosed: X-Powered-By: {x_powered_by}",
                        description=f"X-Powered-By header exposes backend framework/runtime: '{x_powered_by}'.",
                        target=https_url,
                        source_module=self.name,
                        data={"x_powered_by": x_powered_by},
                        remediation="Remove the 'X-Powered-By' header from application server responses.",
                    )
                )

            # 3g. Permissions-Policy
            perm_pol = h.get("permissions-policy")
            if not perm_pol:
                await context.emit_finding(
                    Finding(
                        category=Category.HTTP_HEADER,
                        severity=Severity.LOW,
                        title="Missing Permissions-Policy Header",
                        description="No Permissions-Policy header configured. Browser hardware APIs (camera, microphone, geolocation) are not restricted.",
                        target=https_url,
                        source_module=self.name,
                        data={"header": "Permissions-Policy", "status": "missing"},
                        remediation="Define a 'Permissions-Policy: camera=(), microphone=(), geolocation=()' header to restrict browser features.",
                    )
                )

            # 3h. Cookie Security Flags
            set_cookies = resp_https.headers.get_list("set-cookie") if hasattr(resp_https.headers, "get_list") else []
            for cookie_str in set_cookies:
                c_lower = cookie_str.lower()
                c_name = cookie_str.split("=")[0].strip()
                missing_flags = []
                if "secure" not in c_lower:
                    missing_flags.append("Secure")
                if "httponly" not in c_lower:
                    missing_flags.append("HttpOnly")
                if "samesite" not in c_lower:
                    missing_flags.append("SameSite")

                if missing_flags:
                    await context.emit_finding(
                        Finding(
                            category=Category.HTTP_HEADER,
                            severity=Severity.LOW,
                            title=f"Cookie '{c_name}' Missing Security Flags ({', '.join(missing_flags)})",
                            description=f"Cookie '{c_name}' was issued without the {', '.join(missing_flags)} attribute(s).",
                            target=https_url,
                            source_module=self.name,
                            data={"cookie_name": c_name, "missing_flags": missing_flags},
                            remediation=f"Configure the web application to enforce {', '.join(missing_flags)} on cookie '{c_name}'.",
                        )
                    )
                    break

        await context.update_progress(self.name, 1.0, "Security headers audit completed")
        await context.log("info", f"[Headers] Finished headers audit for {target.domain}")
