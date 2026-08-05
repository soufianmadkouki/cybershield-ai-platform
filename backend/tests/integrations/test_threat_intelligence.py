from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.integrations.threat_intelligence.base import (
    ThreatIntelligenceProvider,
)
from app.integrations.threat_intelligence.normalization import (
    to_vulnerability_create,
)
from app.integrations.threat_intelligence.schemas import (
    NormalizedVulnerabilityRecord,
    RawThreatIntelligenceRecord,
    ThreatIntelligenceProviderName,
)
from app.models import Vulnerability
from app.models.vulnerability_enums import (
    ExploitMaturity,
    VulnerabilitySeverity,
)
from app.services.vulnerability_ingestion import (
    ingest_threat_intelligence_provider,
)


class FakeThreatIntelligenceProvider(
    ThreatIntelligenceProvider,
):
    @property
    def name(self) -> ThreatIntelligenceProviderName:
        return ThreatIntelligenceProviderName.NVD

    def fetch_records(
        self,
        *,
        since: datetime | None = None,
        limit: int | None = None,
    ) -> list[RawThreatIntelligenceRecord]:
        records = [
            RawThreatIntelligenceRecord(
                provider=self.name,
                external_id="nvd-cve-2026-90001",
                payload={
                    "cve_id": "CVE-2026-90001",
                    "title": "Critical test vulnerability",
                    "severity": "critical",
                },
            )
        ]

        if limit is not None:
            return records[:limit]

        return records

    def normalize_record(
        self,
        record: RawThreatIntelligenceRecord,
    ) -> NormalizedVulnerabilityRecord:
        return NormalizedVulnerabilityRecord(
            provider=self.name,
            provider_record_id=record.external_id,
            cve_id=str(record.payload["cve_id"]),
            title=str(record.payload["title"]),
            description="Normalized provider vulnerability.",
            severity=VulnerabilitySeverity.CRITICAL,
            cvss_v3_score=9.8,
            epss_score=0.91,
            is_cisa_kev=True,
            is_patch_available=True,
            exploit_maturity=ExploitMaturity.WEAPONIZED,
            vendor="CyberShield",
            product="Provider Test Product",
            affected_versions=["1.0.0", "1.0.0", "1.0.1"],
            cwe_ids=["CWE-78", "CWE-78"],
            references=[
                "https://example.com/CVE-2026-90001",
                "https://example.com/CVE-2026-90001",
            ],
            published_at=datetime(2026, 8, 5, tzinfo=UTC),
            modified_at=datetime(2026, 8, 5, tzinfo=UTC),
            provider_metadata={
                "feed_version": "test-1",
            },
        )


def test_normalized_record_cleans_provider_values() -> None:
    record = NormalizedVulnerabilityRecord(
        provider=ThreatIntelligenceProviderName.NVD,
        provider_record_id=" nvd-record-1 ",
        cve_id=" cve-2026-90001 ",
        title=" Test vulnerability ",
        affected_versions=["1.0", "1.0", " 2.0 "],
        cwe_ids=["CWE-79", "CWE-79"],
        references=["https://example.com", "https://example.com"],
    )

    assert record.cve_id == "CVE-2026-90001"
    assert record.title == "Test vulnerability"
    assert record.affected_versions == ["1.0", "2.0"]
    assert record.cwe_ids == ["CWE-79"]
    assert record.references == ["https://example.com"]


def test_normalized_record_converts_to_vulnerability_create() -> None:
    provider = FakeThreatIntelligenceProvider()
    raw_record = provider.fetch_records()[0]
    normalized = provider.normalize_record(raw_record)

    payload = to_vulnerability_create(normalized)

    assert payload.cve_id == "CVE-2026-90001"
    assert payload.title == "Critical test vulnerability"
    assert payload.source.value == "nvd"
    assert payload.cvss_v3_score == 9.8
    assert payload.is_cisa_kev is True
    assert payload.affected_versions == ["1.0.0", "1.0.1"]
    assert "threat_intelligence" in payload.metadata_json


def test_provider_ingestion_creates_vulnerability(
    database_session: Session,
) -> None:
    provider = FakeThreatIntelligenceProvider()

    summary = ingest_threat_intelligence_provider(
        database_session,
        provider,
    )

    vulnerability = database_session.scalar(
        select(Vulnerability).where(
            Vulnerability.cve_id == "CVE-2026-90001",
        )
    )

    assert summary.fetched == 1
    assert summary.created == 1
    assert summary.updated == 0
    assert summary.failed == 0

    assert vulnerability is not None
    assert vulnerability.cvss_v3_score == 9.8
    assert vulnerability.epss_score == 0.91
    assert vulnerability.is_cisa_kev is True


def test_provider_ingestion_updates_existing_vulnerability(
    database_session: Session,
) -> None:
    provider = FakeThreatIntelligenceProvider()

    first_summary = ingest_threat_intelligence_provider(
        database_session,
        provider,
    )
    second_summary = ingest_threat_intelligence_provider(
        database_session,
        provider,
    )

    vulnerabilities = list(
        database_session.scalars(
            select(Vulnerability).where(
                Vulnerability.cve_id == "CVE-2026-90001",
            )
        ).all()
    )

    assert first_summary.created == 1
    assert second_summary.updated == 1
    assert len(vulnerabilities) == 1
    assert vulnerabilities[0].references == [
        "https://example.com/CVE-2026-90001",
    ]
