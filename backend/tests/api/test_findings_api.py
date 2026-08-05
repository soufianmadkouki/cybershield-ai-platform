from typing import Any, cast

from fastapi.testclient import TestClient


def build_asset_payload() -> dict[str, Any]:
    return {
        "name": "CyberShield Critical Server",
        "hostname": "cybershield-critical-01",
        "asset_type": "server",
        "ip_address": "10.20.30.40",
        "mac_address": "00:11:22:33:44:66",
        "operating_system": "Ubuntu",
        "operating_system_version": "24.04 LTS",
        "environment": "production",
        "criticality": "critical",
        "status": "active",
        "owner": "CyberShield Engineering",
        "description": "Critical integration-test asset.",
        "tags": {
            "team": "engineering",
        },
        "discovery_source": "manual",
        "external_id": "critical-asset-001",
        "last_seen_at": "2026-08-05T12:00:00Z",
    }


def build_vulnerability_payload() -> dict[str, Any]:
    return {
        "cve_id": "CVE-2026-50001",
        "title": "Critical remote code execution vulnerability",
        "description": "Integration-test vulnerability.",
        "severity": "critical",
        "source": "manual",
        "cvss_v3_score": 9.8,
        "cvss_v3_vector": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        "epss_score": 0.95,
        "epss_percentile": 0.99,
        "is_cisa_kev": True,
        "is_patch_available": True,
        "exploit_maturity": "weaponized",
        "vendor": "CyberShield",
        "product": "Test Service",
        "affected_versions": ["1.0.0"],
        "cwe_ids": ["CWE-78"],
        "references": [],
        "metadata_json": {},
        "published_at": "2026-08-05T12:00:00Z",
        "modified_at": "2026-08-05T12:00:00Z",
    }


def create_asset(
    client: TestClient,
    auth_headers: dict[str, str],
) -> dict[str, Any]:
    response = client.post(
        "/api/v1/assets",
        headers=auth_headers,
        json=build_asset_payload(),
    )

    assert response.status_code == 201, response.text
    return cast(dict[str, Any], response.json())


def create_vulnerability(
    client: TestClient,
    auth_headers: dict[str, str],
) -> dict[str, Any]:
    response = client.post(
        "/api/v1/vulnerabilities",
        headers=auth_headers,
        json=build_vulnerability_payload(),
    )

    assert response.status_code == 201, response.text
    return cast(dict[str, Any], response.json())


def build_finding_payload(
    asset_id: str,
    vulnerability_id: str,
) -> dict[str, Any]:
    return {
        "asset_id": asset_id,
        "vulnerability_id": vulnerability_id,
        "status": "open",
        "remediation_status": "not_started",
        "scanner_source": "manual",
        "scanner_finding_id": "manual-finding-001",
        "risk_score": None,
        "is_exploitable": True,
        "evidence": "Affected service is reachable.",
        "remediation_recommendation": ("Upgrade to the vendor-fixed release."),
        "fixed_version": "1.0.1",
        "metadata_json": {
            "validated_by": "integration-test",
        },
        "first_seen_at": "2026-08-05T12:00:00Z",
        "last_seen_at": "2026-08-05T12:00:00Z",
    }


def create_finding(
    client: TestClient,
    auth_headers: dict[str, str],
) -> dict[str, Any]:
    asset = create_asset(client, auth_headers)
    vulnerability = create_vulnerability(client, auth_headers)

    response = client.post(
        "/api/v1/vulnerabilities/findings",
        headers=auth_headers,
        json=build_finding_payload(
            asset["id"],
            vulnerability["id"],
        ),
    )

    assert response.status_code == 201, response.text
    return cast(dict[str, Any], response.json())


def test_create_finding_calculates_risk_score(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    asset = create_asset(client, auth_headers)
    vulnerability = create_vulnerability(client, auth_headers)

    response = client.post(
        "/api/v1/vulnerabilities/findings",
        headers=auth_headers,
        json=build_finding_payload(
            asset["id"],
            vulnerability["id"],
        ),
    )

    assert response.status_code == 201

    body = response.json()

    assert body["asset_id"] == asset["id"]
    assert body["vulnerability_id"] == vulnerability["id"]
    assert body["status"] == "open"
    assert body["remediation_status"] == "not_started"
    assert body["risk_score"] == 100.0
    assert body["is_exploitable"] is True
    assert body["organization_id"] == auth_headers["X-Organization-ID"]


def test_create_finding_requires_authentication(
    client: TestClient,
) -> None:
    response = client.post(
        "/api/v1/vulnerabilities/findings",
        json={
            "asset_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
            "vulnerability_id": ("3fa85f64-5717-4562-b3fc-2c963f66afa6"),
            "scanner_source": "manual",
            "first_seen_at": "2026-08-05T12:00:00Z",
            "last_seen_at": "2026-08-05T12:00:00Z",
        },
    )

    assert response.status_code == 401


def test_duplicate_finding_is_rejected(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    asset = create_asset(client, auth_headers)
    vulnerability = create_vulnerability(client, auth_headers)

    payload = build_finding_payload(
        asset["id"],
        vulnerability["id"],
    )

    first_response = client.post(
        "/api/v1/vulnerabilities/findings",
        headers=auth_headers,
        json=payload,
    )

    second_response = client.post(
        "/api/v1/vulnerabilities/findings",
        headers=auth_headers,
        json=payload,
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 409
    assert second_response.json()["detail"] == ("This scanner finding already exists for the asset")


def test_finding_rejects_unknown_asset(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    vulnerability = create_vulnerability(client, auth_headers)

    response = client.post(
        "/api/v1/vulnerabilities/findings",
        headers=auth_headers,
        json=build_finding_payload(
            "3fa85f64-5717-4562-b3fc-2c963f66afa6",
            vulnerability["id"],
        ),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == ("Asset not found in the current organization")


def test_finding_rejects_unknown_vulnerability(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    asset = create_asset(client, auth_headers)

    response = client.post(
        "/api/v1/vulnerabilities/findings",
        headers=auth_headers,
        json=build_finding_payload(
            asset["id"],
            "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        ),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Vulnerability not found"


def test_list_findings(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    finding = create_finding(client, auth_headers)

    response = client.get(
        "/api/v1/vulnerabilities/findings",
        headers=auth_headers,
    )

    assert response.status_code == 200

    body = response.json()

    assert body["total"] == 1
    assert body["page"] == 1
    assert body["size"] == 20
    assert body["pages"] == 1
    assert body["items"][0]["id"] == finding["id"]


def test_get_finding(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    finding = create_finding(client, auth_headers)

    response = client.get(
        f"/api/v1/vulnerabilities/findings/{finding['id']}",
        headers=auth_headers,
    )

    assert response.status_code == 200
    assert response.json()["id"] == finding["id"]


def test_get_unknown_finding_returns_404(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    response = client.get(
        ("/api/v1/vulnerabilities/findings/3fa85f64-5717-4562-b3fc-2c963f66afa6"),
        headers=auth_headers,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == ("Asset vulnerability finding not found")


def test_update_finding(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    finding = create_finding(client, auth_headers)

    response = client.patch(
        f"/api/v1/vulnerabilities/findings/{finding['id']}",
        headers=auth_headers,
        json={
            "status": "in_progress",
            "remediation_status": "in_progress",
            "evidence": "Patch validation is in progress.",
            "last_seen_at": "2026-08-05T14:00:00Z",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["status"] == "in_progress"
    assert body["remediation_status"] == "in_progress"
    assert body["evidence"] == "Patch validation is in progress."


def test_filter_findings(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    finding = create_finding(client, auth_headers)

    update_response = client.patch(
        f"/api/v1/vulnerabilities/findings/{finding['id']}",
        headers=auth_headers,
        json={
            "status": "in_progress",
            "remediation_status": "in_progress",
        },
    )

    assert update_response.status_code == 200

    response = client.get(
        ("/api/v1/vulnerabilities/findings?finding_status=in_progress&minimum_risk_score=90"),
        headers=auth_headers,
    )

    assert response.status_code == 200

    body = response.json()

    assert body["total"] == 1
    assert body["items"][0]["id"] == finding["id"]


def test_filter_findings_by_asset_and_vulnerability(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    finding = create_finding(client, auth_headers)

    response = client.get(
        (
            "/api/v1/vulnerabilities/findings"
            f"?asset_id={finding['asset_id']}"
            f"&vulnerability_id={finding['vulnerability_id']}"
        ),
        headers=auth_headers,
    )

    assert response.status_code == 200
    assert response.json()["total"] == 1


def test_delete_finding(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    finding = create_finding(client, auth_headers)

    delete_response = client.delete(
        f"/api/v1/vulnerabilities/findings/{finding['id']}",
        headers=auth_headers,
    )

    get_response = client.get(
        f"/api/v1/vulnerabilities/findings/{finding['id']}",
        headers=auth_headers,
    )

    assert delete_response.status_code == 204
    assert delete_response.content == b""
    assert get_response.status_code == 404


def test_invalid_finding_uuid_returns_422(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    response = client.get(
        "/api/v1/vulnerabilities/findings/not-a-valid-uuid",
        headers=auth_headers,
    )

    assert response.status_code == 422


def test_invalid_risk_score_is_rejected(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    asset = create_asset(client, auth_headers)
    vulnerability = create_vulnerability(client, auth_headers)

    payload = build_finding_payload(
        asset["id"],
        vulnerability["id"],
    )
    payload["risk_score"] = 101

    response = client.post(
        "/api/v1/vulnerabilities/findings",
        headers=auth_headers,
        json=payload,
    )

    assert response.status_code == 422
