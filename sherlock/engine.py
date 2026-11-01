"""
Asynchronous Investigation Engine for Sherlock OSINT Suite.
Coordinates pluggable modules, event dispatching, and findings correlation.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import traceback
from typing import Dict, List, Optional, Type
from .context import InvestigationContext
from .models import Finding, InvestigationResult, Target
from .modules.base import BaseModule
from .modules import ALL_MODULES, MODULE_MAP


class SherlockEngine:
    def __init__(
        self,
        modules: Optional[List[BaseModule]] = None,
        max_concurrency: int = 3,
    ):
        if modules is not None:
            self.modules = modules
        else:
            self.modules = [cls() for cls in ALL_MODULES]
        self.max_concurrency = max_concurrency

    @classmethod
    def from_module_ids(cls, module_ids: List[str]) -> SherlockEngine:
        instances: List[BaseModule] = []
        for mid in module_ids:
            if mid in MODULE_MAP:
                instances.append(MODULE_MAP[mid]())
        return cls(modules=instances)

    async def run(
        self,
        target: Target,
        context: Optional[InvestigationContext] = None,
    ) -> InvestigationResult:
        if context is None:
            context = InvestigationContext(target)

        start_time = datetime.now(timezone.utc)
        await context.log("info", f"=== Starting Sherlock Investigation: {target.domain} (Depth: {target.depth.value}) ===")

        executed_modules: List[str] = []
        sem = asyncio.Semaphore(self.max_concurrency)

        async def run_single_module(mod: BaseModule):
            if context.cancelled:
                return
            async with sem:
                if context.cancelled:
                    return
                executed_modules.append(mod.name)
                try:
                    await context.log("info", f"Starting module: {mod.name}")
                    await mod.run(target, context)
                    await context.log("info", f"Completed module: {mod.name}")
                except asyncio.CancelledError:
                    await context.log("warning", f"Module {mod.name} was cancelled")
                    raise
                except Exception as e:
                    stack = traceback.format_exc()
                    await context.log("error", f"Error in {mod.name}: {e}")

        # Run modules concurrently within the semaphore limit
        tasks = [run_single_module(m) for m in self.modules]
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except asyncio.CancelledError:
            await context.log("warning", "Investigation cancelled by user.")

        end_time = datetime.now(timezone.utc)
        result = InvestigationResult.create(
            target=target,
            findings=context.findings,
            modules_executed=executed_modules,
            start_time=start_time,
            end_time=end_time,
        )

        await context.log(
            "info",
            f"=== Investigation Finished: {result.summary.total_findings} findings recorded. "
            f"Risk Score: {result.summary.risk_score}/100. Duration: {result.summary.duration_seconds}s ===",
        )

        return result
