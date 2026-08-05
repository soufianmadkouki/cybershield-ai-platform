from abc import ABC, abstractmethod
from datetime import datetime

from app.integrations.threat_intelligence.schemas import (
    NormalizedVulnerabilityRecord,
    RawThreatIntelligenceRecord,
    ThreatIntelligenceProviderName,
)


class ThreatIntelligenceProvider(ABC):
    """Base contract implemented by all threat-intelligence providers."""

    @property
    @abstractmethod
    def name(self) -> ThreatIntelligenceProviderName:
        """Return the provider's stable internal name."""

    @abstractmethod
    def fetch_records(
        self,
        *,
        since: datetime | None = None,
        limit: int | None = None,
    ) -> list[RawThreatIntelligenceRecord]:
        """Fetch raw provider records."""

    @abstractmethod
    def normalize_record(
        self,
        record: RawThreatIntelligenceRecord,
    ) -> NormalizedVulnerabilityRecord:
        """Convert a provider record into the CyberShield canonical model."""

    def fetch_normalized_records(
        self,
        *,
        since: datetime | None = None,
        limit: int | None = None,
    ) -> list[NormalizedVulnerabilityRecord]:
        raw_records = self.fetch_records(
            since=since,
            limit=limit,
        )

        return [self.normalize_record(record) for record in raw_records]
