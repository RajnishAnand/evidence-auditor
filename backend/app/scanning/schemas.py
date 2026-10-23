from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    authorization_confirmed: bool


class Evidence(BaseModel):
    source: str
    value: str
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    limitation: str | None = None


class TechnologyObservation(BaseModel):
    product: str
    category: str
    version: str | None = None
    rule_id: str
    observed_value: str
    evidence_source: str
    confidence: float = Field(ge=0, le=1)
    limitation: str
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class VulnerabilityCandidate(BaseModel):
    cve_id: str
    status: str = "candidate"
    product: str
    summary: str
    source: str = "NVD"
    advisory_url: str
    severity: str | None = None
    cvss_score: float | None = None
    published: datetime | None = None
    modified: datetime | None = None
    matched_version: str | None = None
    applicability_confidence: float = Field(ge=0, le=1)
    limitation: str


class ScanStatus(StrEnum):
    completed = "completed"
    blocked = "blocked"
    failed = "failed"


class ScanResult(BaseModel):
    target: str
    final_url: str | None = None
    status: ScanStatus
    http_status: int | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, list[str]] = Field(default_factory=dict)
    referenced_assets: list[str] = Field(default_factory=list)
    technologies: list[TechnologyObservation] = Field(default_factory=list)
    vulnerabilities: list[VulnerabilityCandidate] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    redirects: list[str] = Field(default_factory=list)
