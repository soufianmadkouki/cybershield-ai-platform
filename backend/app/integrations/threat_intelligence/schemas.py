from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.models.vulnerability_enums import (
    ExploitMaturity,
    VulnerabilitySeverity,
)


class ThreatIntelligenceProviderName(StrEnum):
    NVD = "nvd"
    CISA_KEV = "cisa_kev"
    EPSS = "epss"
    GITHUB_ADVISORY = "github_advisory"
    OSV = "osv"
    VENDOR = "vendor"
    OTHER = "other"


class RawThreatIntelligenceRecord(BaseModel):
    provider: ThreatIntelligenceProviderName
    external_id: str = Field(min_length=1, max_length=255)
    payload: dict[str, Any]
    fetched_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )

    @field_validator("external_id")
    @classmethod
    def normalize_external_id(cls, value: str) -> str:
        return value.strip()


class NormalizedVulnerabilityRecord(BaseModel):
    provider: ThreatIntelligenceProviderName
    provider_record_id: str = Field(min_length=1, max_length=255)

    cve_id: str = Field(min_length=1, max_length=32)
    title: str | None = Field(default=None, max_length=500)
    description: str | None = Field(default=None, max_length=20000)

    severity: VulnerabilitySeverity = VulnerabilitySeverity.UNKNOWN

    cvss_v2_score: float | None = Field(default=None, ge=0, le=10)
    cvss_v2_vector: str | None = Field(default=None, max_length=255)

    cvss_v3_score: float | None = Field(default=None, ge=0, le=10)
    cvss_v3_vector: str | None = Field(default=None, max_length=255)

    cvss_v4_score: float | None = Field(default=None, ge=0, le=10)
    cvss_v4_vector: str | None = Field(default=None, max_length=255)

    epss_score: float | None = Field(default=None, ge=0, le=1)
    epss_percentile: float | None = Field(default=None, ge=0, le=1)

    is_cisa_kev: bool = False
    is_patch_available: bool = False
    exploit_maturity: ExploitMaturity = ExploitMaturity.UNKNOWN

    vendor: str | None = Field(default=None, max_length=255)
    product: str | None = Field(default=None, max_length=255)

    affected_versions: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)

    published_at: datetime | None = None
    modified_at: datetime | None = None

    provider_metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("cve_id")
    @classmethod
    def normalize_cve_id(cls, value: str) -> str:
        return value.strip().upper()

    @field_validator(
        "title",
        "description",
        "vendor",
        "product",
        mode="before",
    )
    @classmethod
    def normalize_optional_text(
        cls,
        value: object,
    ) -> object:
        if not isinstance(value, str):
            return value

        normalized = value.strip()
        return normalized or None

    @field_validator(
        "affected_versions",
        "cwe_ids",
        "references",
        mode="after",
    )
    @classmethod
    def deduplicate_string_lists(
        cls,
        values: list[str],
    ) -> list[str]:
        normalized_values: list[str] = []
        seen: set[str] = set()

        for value in values:
            normalized = value.strip()

            if not normalized or normalized in seen:
                continue

            seen.add(normalized)
            normalized_values.append(normalized)

        return normalized_values


class ThreatIntelligenceIngestionAction(StrEnum):
    CREATED = "created"
    UPDATED = "updated"
    SKIPPED = "skipped"
    FAILED = "failed"


class ThreatIntelligenceRecordResult(BaseModel):
    provider: ThreatIntelligenceProviderName
    provider_record_id: str
    cve_id: str | None = None
    action: ThreatIntelligenceIngestionAction
    detail: str | None = None


class ThreatIntelligenceIngestionSummary(BaseModel):
    provider: ThreatIntelligenceProviderName

    fetched: int = 0
    created: int = 0
    updated: int = 0
    skipped: int = 0
    failed: int = 0

    results: list[ThreatIntelligenceRecordResult] = Field(
        default_factory=list,
    )
