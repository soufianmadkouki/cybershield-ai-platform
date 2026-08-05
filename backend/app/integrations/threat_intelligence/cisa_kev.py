from datetime import UTC, datetime
from typing import Any

import httpx

from app.integrations.threat_intelligence.base import (
    ThreatIntelligenceProvider,
)
from app.integrations.threat_intelligence.cisa_kev_schemas import (
    CisaKevCatalog,
    CisaKevVulnerability,
)
from app.integrations.threat_intelligence.schemas import (
    NormalizedVulnerabilityRecord,
    RawThreatIntelligenceRecord,
    ThreatIntelligenceProviderName,
)
from app.models.vulnerability_enums import (
    ExploitMaturity,
    VulnerabilitySeverity,
)

CISA_KEV_JSON_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


class CisaKevProviderError(RuntimeError):
    """Raised when the CISA KEV catalog cannot be retrieved or parsed."""


class CisaKevProvider(ThreatIntelligenceProvider):
    def __init__(
        self,
        *,
        feed_url: str = CISA_KEV_JSON_URL,
        timeout_seconds: float = 30.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.feed_url = feed_url
        self.timeout_seconds = timeout_seconds
        self._client = client

        self._catalog_metadata: dict[str, Any] = {}

    @property
    def name(self) -> ThreatIntelligenceProviderName:
        return ThreatIntelligenceProviderName.CISA_KEV

    def fetch_records(
        self,
        *,
        since: datetime | None = None,
        limit: int | None = None,
    ) -> list[RawThreatIntelligenceRecord]:
        try:
            response = self._get_client().get(
                self.feed_url,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "CyberShield-AI/0.1",
                },
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise CisaKevProviderError(f"Unable to retrieve CISA KEV catalog: {exc}") from exc

        try:
            catalog = CisaKevCatalog.model_validate(response.json())
        except (ValueError, TypeError) as exc:
            raise CisaKevProviderError(f"Invalid CISA KEV catalog response: {exc}") from exc

        self._catalog_metadata = catalog.provider_metadata()

        vulnerabilities = catalog.vulnerabilities

        if since is not None:
            since_date = since.astimezone(UTC).date()

            vulnerabilities = [
                vulnerability
                for vulnerability in vulnerabilities
                if vulnerability.date_added >= since_date
            ]

        if limit is not None:
            vulnerabilities = vulnerabilities[:limit]

        fetched_at = datetime.now(UTC)

        return [
            RawThreatIntelligenceRecord(
                provider=self.name,
                external_id=vulnerability.cve_id,
                payload=vulnerability.model_dump(
                    mode="json",
                    by_alias=True,
                ),
                fetched_at=fetched_at,
            )
            for vulnerability in vulnerabilities
        ]

    def normalize_record(
        self,
        record: RawThreatIntelligenceRecord,
    ) -> NormalizedVulnerabilityRecord:
        if record.provider != self.name:
            raise ValueError("CISA KEV provider received a record from another provider")

        vulnerability = CisaKevVulnerability.model_validate(
            record.payload,
        )

        published_at = datetime.combine(
            vulnerability.date_added,
            datetime.min.time(),
            tzinfo=UTC,
        )

        references = self._build_references(
            vulnerability.notes,
        )

        return NormalizedVulnerabilityRecord(
            provider=self.name,
            provider_record_id=record.external_id,
            cve_id=vulnerability.cve_id,
            title=vulnerability.vulnerability_name,
            description=vulnerability.short_description,
            severity=VulnerabilitySeverity.UNKNOWN,
            is_cisa_kev=True,
            is_patch_available=False,
            exploit_maturity=ExploitMaturity.FUNCTIONAL,
            vendor=vulnerability.vendor_project,
            product=vulnerability.product,
            cwe_ids=vulnerability.cwes,
            references=references,
            published_at=published_at,
            modified_at=published_at,
            provider_metadata={
                **self._catalog_metadata,
                "date_added": vulnerability.date_added.isoformat(),
                "due_date": vulnerability.due_date.isoformat(),
                "required_action": vulnerability.required_action,
                "known_ransomware_campaign_use": (vulnerability.known_ransomware_campaign_use),
                "notes": vulnerability.notes,
                "fetched_at": record.fetched_at.isoformat(),
            },
        )

    def close(self) -> None:
        if self._client is not None:
            self._client.close()

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                follow_redirects=True,
            )

        return self._client

    @staticmethod
    def _build_references(notes: str) -> list[str]:
        references: list[str] = []

        for value in notes.split():
            normalized = value.strip(" ,;()[]")

            if normalized.startswith(
                ("https://", "http://"),
            ):
                references.append(normalized)

        return references
