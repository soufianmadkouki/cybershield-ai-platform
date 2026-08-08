from typing import Any, cast

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.integrations.threat_intelligence.epss import (
    EpssProvider,
    EpssProviderError,
)
from app.integrations.threat_intelligence.schemas import (
    ThreatIntelligenceProviderName,
)
from app.models import Vulnerability
from app.models.vulnerability_enums import (
    ExploitMaturity,
    VulnerabilitySeverity,
    VulnerabilitySource,
)
from app.services.vulnerability_ingestion import (
    ingest_threat_intelligence_provider,
)

TEST_EPSS_RESPONSE = {
    "status": "OK",
    "status-code": 200,
    "version": "1.0",
    "access": "public",
    "total": 2,
    "offset": 0,
    "limit": 100,
    "data": [
        {
            "cve": "CVE-2026-63077",
            "epss": "0.912340000",
            "percentile": "0.998700000",
            "date": "2026-08-05",
        },
        {
            "cve": "CVE-2026-18556",
            "epss": "0.456780000",
            "percentile": "0.942100000",
            "date": "2026-08-05",
        },
    ],
}


def build_mock_client(
    *,
    status_code: int = 200,
    payload: object = TEST_EPSS_RESPONSE,
) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/data/v1/epss"
        assert "CVE-2026-63077" in request.url.params["cve"]

        return httpx.Response(
            status_code=status_code,
            json=payload,
            request=request,
        )

    return httpx.Client(
        transport=httpx.MockTransport(handler),
    )


def test_epss_provider_normalizes_cve_ids() -> None:
    provider = EpssProvider(
        [
            " cve-2026-63077 ",
            "CVE-2026-63077",
            "CVE-2026-18556",
        ],
        client=build_mock_client(),
    )

    assert provider.cve_ids == [
        "CVE-2026-63077",
        "CVE-2026-18556",
    ]


def test_epss_fetches_and_normalizes_records() -> None:
    provider = EpssProvider(
        [
            "CVE-2026-63077",
            "CVE-2026-18556",
        ],
        client=build_mock_client(),
    )

    records = provider.fetch_records()
    normalized = provider.normalize_record(records[0])

    assert len(records) == 2
    assert normalized.cve_id == "CVE-2026-63077"
    assert normalized.epss_score == pytest.approx(0.91234)
    assert normalized.epss_percentile == pytest.approx(0.9987)
    assert normalized.provider_metadata["score_date"] == "2026-08-05"


def test_epss_enriches_existing_vulnerability(
    database_session: Session,
) -> None:
    database_session.add(
        Vulnerability(
            cve_id="CVE-2026-63077",
            title="JetBrains TeamCity vulnerability",
            severity=VulnerabilitySeverity.CRITICAL,
            source=VulnerabilitySource.CISA_KEV,
            is_cisa_kev=True,
            exploit_maturity=ExploitMaturity.FUNCTIONAL,
            vendor="JetBrains",
            product="TeamCity",
        )
    )
    database_session.commit()

    epss_records = cast(
        list[dict[str, Any]],
        TEST_EPSS_RESPONSE["data"],
    )

    provider = EpssProvider(
        ["CVE-2026-63077"],
        client=build_mock_client(
            payload={
                **TEST_EPSS_RESPONSE,
                "total": 1,
                "data": [epss_records[0]],
            },
        ),
    )

    summary = ingest_threat_intelligence_provider(
        database_session,
        provider,
    )

    vulnerability = database_session.scalar(
        select(Vulnerability).where(
            Vulnerability.cve_id == "CVE-2026-63077",
        )
    )

    assert summary.updated == 1
    assert vulnerability is not None
    assert vulnerability.epss_score == pytest.approx(0.91234)
    assert vulnerability.epss_percentile == pytest.approx(0.9987)

    # EPSS enrichment must not remove existing provider data.
    assert vulnerability.is_cisa_kev is True
    assert vulnerability.vendor == "JetBrains"
    assert vulnerability.product == "TeamCity"
    assert vulnerability.severity == VulnerabilitySeverity.CRITICAL

    metadata = vulnerability.metadata_json["threat_intelligence"]

    assert "epss" in metadata


def test_epss_rejects_empty_cve_list() -> None:
    with pytest.raises(
        ValueError,
        match="At least one CVE ID is required",
    ):
        EpssProvider([])


def test_epss_http_failure_raises_provider_error() -> None:
    provider = EpssProvider(
        ["CVE-2026-63077"],
        client=build_mock_client(status_code=503),
    )

    with pytest.raises(
        EpssProviderError,
        match="Unable to retrieve FIRST EPSS scores",
    ):
        provider.fetch_records()


def test_epss_invalid_payload_raises_provider_error() -> None:
    provider = EpssProvider(
        ["CVE-2026-63077"],
        client=build_mock_client(
            payload={"invalid": "response"},
        ),
    )

    with pytest.raises(
        EpssProviderError,
        match="Invalid FIRST EPSS response",
    ):
        provider.fetch_records()


def test_epss_rejects_record_from_another_provider() -> None:
    from app.integrations.threat_intelligence.schemas import (
        RawThreatIntelligenceRecord,
    )

    provider = EpssProvider(
        ["CVE-2026-63077"],
        client=build_mock_client(),
    )

    record = RawThreatIntelligenceRecord(
        provider=ThreatIntelligenceProviderName.NVD,
        external_id="CVE-2026-63077",
        payload={
            "cve": "CVE-2026-63077",
            "epss": 0.9,
            "percentile": 0.99,
            "date": "2026-08-05",
        },
    )

    with pytest.raises(
        ValueError,
        match="record from another provider",
    ):
        provider.normalize_record(record)
