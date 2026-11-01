import asyncio
import pytest

from sherlock.context import InvestigationContext
from sherlock.engine import SherlockEngine
from sherlock.models import Category, Finding, Severity, Target
from sherlock.modules.base import BaseModule


class DummySuccessModule(BaseModule):
    module_id = "dummy_success"
    name = "Dummy Success"
    description = "Dummy success description"
    category = Category.GENERAL

    async def run(self, target: Target, context: InvestigationContext) -> None:
        await context.log("info", "Dummy module running")
        await context.emit_finding(
            Finding(
                category=Category.GENERAL,
                severity=Severity.LOW,
                title="Dummy Low Finding",
                description="A test finding",
                target=target.domain,
                source_module=self.name,
            )
        )


class DummyErrorModule(BaseModule):
    module_id = "dummy_error"
    name = "Dummy Error"
    description = "Dummy error description"
    category = Category.GENERAL

    async def run(self, target: Target, context: InvestigationContext) -> None:
        raise RuntimeError("Controlled failure")


@pytest.mark.asyncio
async def test_engine_resilience():
    target = Target(domain="test.local")
    engine = SherlockEngine(modules=[DummySuccessModule(), DummyErrorModule()])

    logs = []
    context = InvestigationContext(target)
    context.on_log = lambda lvl, msg: logs.append((lvl, msg))

    result = await engine.run(target, context)

    assert result.summary.total_findings == 1
    assert result.findings[0].title == "Dummy Low Finding"
    assert result.summary.risk_score == 5
    assert any("Error in Dummy Error" in msg for lvl, msg in logs)


@pytest.mark.asyncio
async def test_engine_cancellation():
    class SlowModule(BaseModule):
        module_id = "slow"
        name = "Slow"
        description = "Slow"
        category = Category.GENERAL

        async def run(self, target: Target, context: InvestigationContext) -> None:
            for _ in range(50):
                if context.cancelled:
                    return
                await asyncio.sleep(0.05)

    target = Target(domain="test.local")
    engine = SherlockEngine(modules=[SlowModule()])
    context = InvestigationContext(target)

    async def cancel_later():
        await asyncio.sleep(0.08)
        context.cancel()

    asyncio.create_task(cancel_later())
    result = await engine.run(target, context)
    assert result is not None
