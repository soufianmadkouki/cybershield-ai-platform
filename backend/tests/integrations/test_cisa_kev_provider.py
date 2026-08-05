from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.integrations.threat_intelligence.cisa_kev import (
    CISA_KEV_JSON_URL,
    CisaKevProvider,
    CisaKevProviderError,
)
from app.models import Vulnerability
from app.services.vulnerability_ingestion import (
    ingest_threat_intelligence_provider,
)

TEST_CATALOG = {
    "title": "CISA Known Exploited Vulnerabilities Catalog",
    "catalogVersion": "2026.08.05",
    "dateReleased": "2026-08-05T10:00:00.000Z",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-90001",
            "vendorProject": "CyberShield",
            "product": "Security Platform",
            "vulnerabilityName": ("CyberShield Security Platform Code Execution Vulnerability"),
            "dateAdded": "2026-08-05",
            "shortDescription": (
                "CyberShield Security Platform contains a code execution vulnerability."
            ),
            "requiredAction": ("Apply mitigations per vendor instructions."),
            "dueDate": "2026-08-26",
            "knownRansomwareCampaignUse": "Known",
            "notes": (
                "See https://example.com/advisories/CVE-2026-90001 for remediation information."
            ),
            "cwes": ["CWE-78"],
        },
        {
            "cveID": "CVE-2026-90002",
            "vendorProject": "Example Vendor",
            "product": "Example Product",
            "vulnerabilityName": "Example Authentication Bypass",
            "dateAdded": "2026-07-01",
            "shortDescription": ("Example Product contains an authentication bypass."),
            "requiredAction": "Apply vendor updates.",
            "dueDate": "2026-07-22",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
            "cwes": ["CWE-287"],
        },
    ],
}


def build_mock_client(
    *,
    status_code: int = 200,
    payload: object = TEST_CATALOG,
) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == CISA_KEV_JSON_URL

        return httpx.Response(
            status_code=status_code,
            json=payload,
            request=request,
        )

    return httpx.Client(
        transport=httpx.MockTransport(handler),
    )


def test_cisa_kev_fetches_and_normalizes_records() -> None:
    provider = CisaKevProvider(
        client=build_mock_client(),
    )

    records = provider.fetch_records(limit=1)
    normalized = provider.normalize_record(records[0])

    assert len(records) == 1
    assert normalized.cve_id == "CVE-2026-90001"
    assert normalized.is_cisa_kev is True
    assert normalized.vendor == "CyberShield"
    assert normalized.product == "Security Platform"
    assert normalized.cwe_ids == ["CWE-78"]
    assert normalized.references == ["https://example.com/advisories/CVE-2026-90001"]
    assert normalized.provider_metadata["due_date"] == "2026-08-26"
    assert normalized.provider_metadata["known_ransomware_campaign_use"] == "Known"


def test_cisa_kev_filters_records_by_date() -> None:
    provider = CisaKevProvider(
        client=build_mock_client(),
    )

    records = provider.fetch_records(
        since=datetime(2026, 8, 1, tzinfo=UTC),
    )

    assert len(records) == 1
    assert records[0].external_id == "CVE-2026-90001"


def test_cisa_kev_ingestion_creates_catalog_entry(
    database_session: Session,
) -> None:
    provider = CisaKevProvider(
        client=build_mock_client(),
    )

    summary = ingest_threat_intelligence_provider(
        database_session,
        provider,
        limit=1,
    )

    vulnerability = database_session.scalar(
        select(Vulnerability).where(
            Vulnerability.cve_id == "CVE-2026-90001",
        )
    )

    assert summary.fetched == 1
    assert summary.created == 1
    assert summary.failed == 0

    assert vulnerability is not None
    assert vulnerability.is_cisa_kev is True
    assert vulnerability.vendor == "CyberShield"
    assert vulnerability.product == "Security Platform"

    provider_metadata = vulnerability.metadata_json["threat_intelligence"]["cisa_kev"]

    assert provider_metadata["catalog_version"] == "2026.08.05"
    assert provider_metadata["required_action"] == ("Apply mitigations per vendor instructions.")


def test_cisa_kev_http_failure_raises_provider_error() -> None:
    provider = CisaKevProvider(
        client=build_mock_client(
            status_code=503,
        ),
    )

    with pytest.raises(
        CisaKevProviderError,
        match="Unable to retrieve CISA KEV catalog",
    ):
        provider.fetch_records()


def test_cisa_kev_invalid_payload_raises_provider_error() -> None:
    provider = CisaKevProvider(
        client=build_mock_client(
            payload={
                "invalid": "catalog",
            },
        ),
    )

    with pytest.raises(
        CisaKevProviderError,
        match="Invalid CISA KEV catalog response",
    ):
        provider.fetch_records()
