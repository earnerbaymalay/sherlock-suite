"""
Strongly-typed entity models for Sherlock OSINT & Attack Surface Management.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class InvestigationDepth(str, Enum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def score_weight(self) -> int:
        weights = {
            Severity.INFO: 0,
            Severity.LOW: 5,
            Severity.MEDIUM: 15,
            Severity.HIGH: 30,
            Severity.CRITICAL: 50,
        }
        return weights.get(self, 0)

    @property
    def style_color(self) -> str:
        colors = {
            Severity.INFO: "cyan",
            Severity.LOW: "green",
            Severity.MEDIUM: "yellow",
            Severity.HIGH: "magenta",
            Severity.CRITICAL: "red",
        }
        return colors.get(self, "white")


class ClientType(str, Enum):
    BUSINESS = "business"
    PERSON = "person"


class ClientProfile(BaseModel):
    client_type: ClientType = ClientType.BUSINESS
    name: Optional[str] = None
    company: Optional[str] = None
    domain: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    notes: Optional[str] = None


class Category(str, Enum):
    DNS = "DNS"
    CERTIFICATE = "Certificate"
    HTTP_HEADER = "HTTP Headers"
    WHOIS_RDAP = "WHOIS / RDAP"
    PORT_SURFACE = "Surface Ports"
    DUE_DILIGENCE = "Due Diligence"
    GENERAL = "General"


class Target(BaseModel):
    domain: str = ""
    depth: InvestigationDepth = InvestigationDepth.STANDARD
    organization: Optional[str] = None
    timeout: float = Field(default=15.0, ge=1.0, le=120.0)
    client_profile: Optional[ClientProfile] = None

    @field_validator("domain", mode="before")
    @classmethod
    def clean_domain(cls, v: Any) -> str:
        if not v:
            return ""
        v = str(v).strip().lower()
        # Strip protocol if provided (e.g. https://example.com/test -> example.com)
        v = re.sub(r"^https?://", "", v)
        # Strip path, query params, or hash fragments
        v = v.split("/")[0].split("?")[0].split("#")[0]
        # Strip userinfo if credentials were present (e.g. user:pass@domain.com)
        if "@" in v:
            v = v.split("@", 1)[1]
        # Strip port if present
        v = v.split(":")[0]
        # Strip trailing dot from FQDN
        v = v.rstrip(".")
        if not v or "." not in v:
            raise ValueError(f"Invalid domain name: {v}")
        return v

    @model_validator(mode="after")
    def ensure_domain(self) -> Target:
        if not self.domain:
            if self.client_profile:
                if self.client_profile.domain:
                    self.domain = self.clean_domain(self.client_profile.domain)
                elif self.client_profile.email and "@" in self.client_profile.email:
                    self.domain = self.clean_domain(self.client_profile.email.split("@")[1])
                else:
                    self.domain = "due-diligence.local"
            else:
                raise ValueError("Target domain cannot be empty")
        return self

    @classmethod
    def from_client_profile(
        cls,
        profile: ClientProfile,
        depth: InvestigationDepth = InvestigationDepth.STANDARD,
    ) -> Target:
        domain = profile.domain or ""
        if not domain and profile.email and "@" in profile.email:
            try:
                domain = profile.email.split("@")[1].strip()
            except Exception:
                domain = ""
        if not domain:
            domain = "due-diligence.local"
        return cls(domain=domain, depth=depth, client_profile=profile)


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    category: Category
    severity: Severity = Severity.INFO
    title: str
    description: str
    target: str
    source_module: str
    data: Dict[str, Any] = Field(default_factory=dict)
    remediation: Optional[str] = None

    model_config = ConfigDict(frozen=False)


class InvestigationSummary(BaseModel):
    target_domain: str
    depth: InvestigationDepth
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    total_findings: int = 0
    severity_counts: Dict[str, int] = Field(default_factory=dict)
    subdomains_count: int = 0
    subdomains: List[str] = Field(default_factory=list)
    risk_score: int = Field(default=0, ge=0, le=100)


class InvestigationResult(BaseModel):
    target: Target
    summary: InvestigationSummary
    findings: List[Finding] = Field(default_factory=list)
    modules_executed: List[str] = Field(default_factory=list)

    @classmethod
    def create(
        cls,
        target: Target,
        findings: List[Finding],
        modules_executed: List[str],
        start_time: datetime,
        end_time: datetime,
    ) -> InvestigationResult:
        duration = max(0.0, (end_time - start_time).total_seconds())

        # Subdomains aggregation
        subdomains: set[str] = set()
        for f in findings:
            if "subdomain" in f.data:
                subdomains.add(f.data["subdomain"])
            if "subdomains" in f.data and isinstance(f.data["subdomains"], list):
                subdomains.update(f.data["subdomains"])

        # Count severities
        sev_counts: Dict[str, int] = {s.value: 0 for s in Severity}
        total_risk_penalty = 0
        for f in findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
            total_risk_penalty += f.severity.score_weight

        # Normalize risk score out of 100
        risk_score = min(100, total_risk_penalty)

        summary = InvestigationSummary(
            target_domain=target.domain,
            depth=target.depth,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=round(duration, 2),
            total_findings=len(findings),
            severity_counts=sev_counts,
            subdomains_count=len(subdomains),
            subdomains=sorted(list(subdomains)),
            risk_score=risk_score,
        )

        return cls(
            target=target,
            summary=summary,
            findings=findings,
            modules_executed=modules_executed,
        )
