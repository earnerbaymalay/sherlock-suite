"""
Base interface for all Sherlock OSINT discovery modules.
"""

from __future__ import annotations

import abc
from ..models import Category, Target
from ..context import InvestigationContext


class BaseModule(abc.ABC):
    module_id: str
    name: str
    description: str
    category: Category
    default_enabled: bool = True

    @abc.abstractmethod
    async def run(self, target: Target, context: InvestigationContext) -> None:
        """
        Execute the OSINT investigation module.
        Should emit findings via `await context.emit_finding(finding)`
        and logs via `await context.log(level, msg)`.
        Must check `context.cancelled` periodically.
        """
        raise NotImplementedError
