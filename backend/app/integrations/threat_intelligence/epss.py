from collections.abc import Iterable
from datetime import UTC, datetime

import httpx

from app.integrations.threat_intelligence.base import (
    ThreatIntelligenceProvider,
)
from app.integrations.threat_intelligence.epss_schemas import (
    EpssApiResponse,
    EpssScoreRecord,
)
from app.integrations.threat_intelligence.schemas import (
    NormalizedVulnerabilityRecord,
    RawThreatIntelligenceRecord,
    ThreatIntelligenceProviderName,
)
from app.models.vulnerability_enums import VulnerabilitySeverity

EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_MAX_CVE_QUERY_LENGTH = 2000


class EpssProviderError(RuntimeError):
    """Raised when EPSS data cannot be retrieved or parsed."""


class EpssProvider(ThreatIntelligenceProvider):
    def __init__(
        self,
        cve_ids: Iterable[str],
        *,
        api_url: str = EPSS_API_URL,
        timeout_seconds: float = 30.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.api_url = api_url
        self.timeout_seconds = timeout_seconds
        self._client = client

        self.cve_ids = self._normalize_cve_ids(cve_ids)

        if not self.cve_ids:
            raise ValueError("At least one CVE ID is required")

        joined_cves = ",".join(self.cve_ids)

        if len(joined_cves) > EPSS_MAX_CVE_QUERY_LENGTH:
            raise ValueError("The EPSS CVE query exceeds the supported maximum length")

    @property
    def name(self) -> ThreatIntelligenceProviderName:
        return ThreatIntelligenceProviderName.EPSS

    def fetch_records(
        self,
        *,
        since: datetime | None = None,
        limit: int | None = None,
    ) -> list[RawThreatIntelligenceRecord]:
        params: dict[str, str | int] = {
            "cve": ",".join(self.cve_ids),
            "envelope": "true",
        }

        if since is not None:
            params["date"] = since.astimezone(UTC).date().isoformat()

        if limit is not None:
            params["limit"] = limit

        try:
            response = self._get_client().get(
                self.api_url,
                params=params,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "CyberShield-AI/0.1",
                },
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise EpssProviderError(f"Unable to retrieve FIRST EPSS scores: {exc}") from exc

        try:
            api_response = EpssApiResponse.model_validate(
                response.json(),
            )
        except (ValueError, TypeError) as exc:
            raise EpssProviderError(f"Invalid FIRST EPSS response: {exc}") from exc

        fetched_at = datetime.now(UTC)

        return [
            RawThreatIntelligenceRecord(
                provider=self.name,
                external_id=score.cve,
                payload=score.model_dump(mode="json"),
                fetched_at=fetched_at,
            )
            for score in api_response.data
        ]

    def normalize_record(
        self,
        record: RawThreatIntelligenceRecord,
    ) -> NormalizedVulnerabilityRecord:
        if record.provider != self.name:
            raise ValueError("EPSS provider received a record from another provider")

        score = EpssScoreRecord.model_validate(record.payload)

        score_datetime = datetime.combine(
            score.date,
            datetime.min.time(),
            tzinfo=UTC,
        )

        return NormalizedVulnerabilityRecord(
            provider=self.name,
            provider_record_id=record.external_id,
            cve_id=score.cve,
            title=score.cve,
            severity=VulnerabilitySeverity.UNKNOWN,
            epss_score=score.epss,
            epss_percentile=score.percentile,
            modified_at=score_datetime,
            provider_metadata={
                "score_date": score.date.isoformat(),
                "epss": score.epss,
                "percentile": score.percentile,
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
    def _normalize_cve_ids(
        cve_ids: Iterable[str],
    ) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()

        for cve_id in cve_ids:
            value = cve_id.strip().upper()

            if not value or value in seen:
                continue

            seen.add(value)
            normalized.append(value)

        return normalized
