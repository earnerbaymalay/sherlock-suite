import pytest
from datetime import datetime, timezone
from sherlock.models import (
    Category,
    Finding,
    InvestigationDepth,
    InvestigationResult,
    Severity,
    Target,
)


def test_target_cleaning():
    t1 = Target(domain="https://example.com/some/path?query=1")
    assert t1.domain == "example.com"
    assert t1.depth == InvestigationDepth.STANDARD

    t2 = Target(domain="HTTP://SUB.EXAMPLE.ORG:8080/")
    assert t2.domain == "sub.example.org"

    # Edge cases: URL with user credentials, trailing dot
    t3 = Target(domain="https://user:password@target.company.com:8443/api")
    assert t3.domain == "target.company.com"

    t4 = Target(domain="example.org.")
    assert t4.domain == "example.org"

    with pytest.raises(ValueError):
        Target(domain="")

    with pytest.raises(ValueError):
        Target(domain="invalid_no_dot")


def test_severity_weights():
    assert Severity.CRITICAL.score_weight == 50
    assert Severity.HIGH.score_weight == 30
    assert Severity.MEDIUM.score_weight == 15
    assert Severity.LOW.score_weight == 5
    assert Severity.INFO.score_weight == 0


def test_investigation_result_aggregation():
    target = Target(domain="example.com")
    f1 = Finding(
        category=Category.DNS,
        severity=Severity.HIGH,
        title="Insecure SPF",
        description="SPF +all",
        target="example.com",
        source_module="dns_scanner",
        data={"subdomain": "mail.example.com"},
    )
    f2 = Finding(
        category=Category.HTTP_HEADER,
        severity=Severity.MEDIUM,
        title="Missing HSTS",
        description="No HSTS",
        target="example.com",
        source_module="http_headers",
        data={"subdomains": ["api.example.com", "mail.example.com"]},
    )

    t0 = datetime.now(timezone.utc)
    res = InvestigationResult.create(
        target=target,
        findings=[f1, f2],
        modules_executed=["dns_scanner", "http_headers"],
        start_time=t0,
        end_time=t0,
    )

    assert res.summary.total_findings == 2
    assert res.summary.risk_score == 45  # 30 + 15
    assert res.summary.subdomains_count == 2
    assert "mail.example.com" in res.summary.subdomains
    assert "api.example.com" in res.summary.subdomains
