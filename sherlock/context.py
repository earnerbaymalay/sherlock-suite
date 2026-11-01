"""
Investigation Context and Event Dispatcher for Sherlock.
"""

from __future__ import annotations

import asyncio
from typing import Callable, Coroutine, Dict, List, Optional, Set, Any
from .models import Finding, Target


class InvestigationContext:
    def __init__(self, target: Target):
        self.target = target
        self.findings: List[Finding] = []
        self.discovered_subdomains: Set[str] = {target.domain}
        self.discovered_ips: Set[str] = set()
        self.cancelled = False
        self._lock = asyncio.Lock()

        # Callbacks for UI updates
        # fn(level: str, message: str)
        self.on_log: Optional[Callable[[str, str], Any]] = None
        # fn(finding: Finding)
        self.on_finding: Optional[Callable[[Finding], Any]] = None
        # fn(module_name: str, progress: float, status_text: str)
        self.on_progress: Optional[Callable[[str, float, str], Any]] = None

    def cancel(self):
        self.cancelled = True

    async def log(self, level: str, message: str):
        if self.on_log:
            try:
                res = self.on_log(level, message)
                if asyncio.iscoroutine(res):
                    await res
            except Exception:
                pass

    async def emit_finding(self, finding: Finding):
        async with self._lock:
            self.findings.append(finding)
            if "subdomain" in finding.data:
                self.discovered_subdomains.add(finding.data["subdomain"])
            if "subdomains" in finding.data and isinstance(finding.data["subdomains"], list):
                self.discovered_subdomains.update(finding.data["subdomains"])
            if "ip" in finding.data:
                self.discovered_ips.add(finding.data["ip"])
            if "ips" in finding.data and isinstance(finding.data["ips"], list):
                self.discovered_ips.update(finding.data["ips"])

        if self.on_finding:
            try:
                res = self.on_finding(finding)
                if asyncio.iscoroutine(res):
                    await res
            except Exception:
                pass

    async def update_progress(self, module_name: str, progress: float, status_text: str):
        if self.on_progress:
            try:
                res = self.on_progress(module_name, progress, status_text)
                if asyncio.iscoroutine(res):
                    await res
            except Exception:
                pass
