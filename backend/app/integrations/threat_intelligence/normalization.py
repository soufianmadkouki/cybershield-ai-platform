from typing import Any

from app.integrations.threat_intelligence.schemas import (
    NormalizedVulnerabilityRecord,
    ThreatIntelligenceProviderName,
)
from app.models.vulnerability_enums import (
    ExploitMaturity,
    VulnerabilitySeverity,
    VulnerabilitySource,
)
from app.schemas.vulnerability import VulnerabilityCreate

PROVIDER_SOURCE_MAP = {
    ThreatIntelligenceProviderName.NVD: VulnerabilitySource.NVD,
    ThreatIntelligenceProviderName.CISA_KEV: VulnerabilitySource.CISA_KEV,
    ThreatIntelligenceProviderName.EPSS: VulnerabilitySource.OTHER,
    ThreatIntelligenceProviderName.GITHUB_ADVISORY: VulnerabilitySource.OTHER,
    ThreatIntelligenceProviderName.OSV: VulnerabilitySource.OTHER,
    ThreatIntelligenceProviderName.VENDOR: VulnerabilitySource.VENDOR,
    ThreatIntelligenceProviderName.OTHER: VulnerabilitySource.OTHER,
}


def merge_unique_strings(
    current_values: list[str],
    incoming_values: list[str],
) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()

    for value in [*current_values, *incoming_values]:
        normalized = value.strip()

        if not normalized or normalized in seen:
            continue

        seen.add(normalized)
        merged.append(normalized)

    return merged


def merge_metadata(
    current_metadata: dict[str, Any],
    incoming_metadata: dict[str, Any],
) -> dict[str, Any]:
    return {
        **current_metadata,
        **incoming_metadata,
    }


def build_provider_metadata(
    record: NormalizedVulnerabilityRecord,
) -> dict[str, Any]:
    provider_name = record.provider.value

    return {
        "threat_intelligence": {
            provider_name: {
                "provider_record_id": record.provider_record_id,
                **record.provider_metadata,
            },
        },
    }


def to_vulnerability_create(
    record: NormalizedVulnerabilityRecord,
) -> VulnerabilityCreate:
    title = record.title or record.cve_id

    return VulnerabilityCreate(
        cve_id=record.cve_id,
        title=title,
        description=record.description,
        severity=record.severity,
        source=PROVIDER_SOURCE_MAP[record.provider],
        cvss_v2_score=record.cvss_v2_score,
        cvss_v2_vector=record.cvss_v2_vector,
        cvss_v3_score=record.cvss_v3_score,
        cvss_v3_vector=record.cvss_v3_vector,
        cvss_v4_score=record.cvss_v4_score,
        cvss_v4_vector=record.cvss_v4_vector,
        epss_score=record.epss_score,
        epss_percentile=record.epss_percentile,
        is_cisa_kev=record.is_cisa_kev,
        is_patch_available=record.is_patch_available,
        exploit_maturity=record.exploit_maturity,
        vendor=record.vendor,
        product=record.product,
        affected_versions=record.affected_versions,
        cwe_ids=record.cwe_ids,
        references=record.references,
        metadata_json=build_provider_metadata(record),
        published_at=record.published_at,
        modified_at=record.modified_at,
    )


def choose_severity(
    current: VulnerabilitySeverity,
    incoming: VulnerabilitySeverity,
) -> VulnerabilitySeverity:
    ranking = {
        VulnerabilitySeverity.UNKNOWN: 0,
        VulnerabilitySeverity.INFORMATIONAL: 1,
        VulnerabilitySeverity.LOW: 2,
        VulnerabilitySeverity.MEDIUM: 3,
        VulnerabilitySeverity.HIGH: 4,
        VulnerabilitySeverity.CRITICAL: 5,
    }

    if ranking[incoming] >= ranking[current]:
        return incoming

    return current


def choose_exploit_maturity(
    current: ExploitMaturity,
    incoming: ExploitMaturity,
) -> ExploitMaturity:
    ranking = {
        ExploitMaturity.UNKNOWN: 0,
        ExploitMaturity.NONE: 1,
        ExploitMaturity.PROOF_OF_CONCEPT: 2,
        ExploitMaturity.FUNCTIONAL: 3,
        ExploitMaturity.WEAPONIZED: 4,
    }

    if ranking[incoming] >= ranking[current]:
        return incoming

    return current
