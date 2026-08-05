from typing import Any, cast

from fastapi.testclient import TestClient


def build_vulnerability_payload(
    *,
    cve_id: str = "CVE-2026-10001",
    title: str = "Remote code execution in CyberShield test service",
) -> dict[str, Any]:
    return {
        "cve_id": cve_id,
        "title": title,
        "description": "Integration-test vulnerability.",
        "severity": "critical",
        "source": "manual",
        "cvss_v3_score": 9.8,
        "cvss_v3_vector": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        "epss_score": 0.92,
        "epss_percentile": 0.98,
        "is_cisa_kev": True,
        "is_patch_available": True,
        "exploit_maturity": "weaponized",
        "vendor": "CyberShield",
        "product": "Test Service",
        "affected_versions": ["1.0.0", "1.0.1"],
        "cwe_ids": ["CWE-78"],
        "references": [
            "https://example.com/security/CVE-2026-10001",
        ],
        "metadata_json": {
            "environment": "test",
        },
        "published_at": "2026-08-05T12:00:00Z",
        "modified_at": "2026-08-05T12:00:00Z",
    }


def create_vulnerability(
    client: TestClient,
    auth_headers: dict[str, str],
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    response = client.post(
        "/api/v1/vulnerabilities",
        headers=auth_headers,
        json=payload or build_vulnerability_payload(),
    )

    assert response.status_code == 201, response.text
    return cast(dict[str, Any], response.json())


def test_create_vulnerability(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    payload = build_vulnerability_payload()

    response = client.post(
        "/api/v1/vulnerabilities",
        headers=auth_headers,
        json=payload,
    )

    assert response.status_code == 201

    body = response.json()

    assert body["cve_id"] == "CVE-2026-10001"
    assert body["severity"] == "critical"
    assert body["cvss_v3_score"] == 9.8
    assert body["epss_score"] == 0.92
    assert body["is_cisa_kev"] is True
    assert body["is_patch_available"] is True
    assert body["id"]


def test_create_vulnerability_requires_authentication(
    client: TestClient,
) -> None:
    response = client.post(
        "/api/v1/vulnerabilities",
        json=build_vulnerability_payload(),
    )

    assert response.status_code == 401


def test_duplicate_cve_id_is_rejected(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    first_response = client.post(
        "/api/v1/vulnerabilities",
        headers=auth_headers,
        json=build_vulnerability_payload(),
    )

    second_response = client.post(
        "/api/v1/vulnerabilities",
        headers=auth_headers,
        json=build_vulnerability_payload(
            title="Duplicate vulnerability",
        ),
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 409
    assert second_response.json()["detail"] == ("A vulnerability with this CVE ID already exists")


def test_cve_id_is_normalized(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    payload = build_vulnerability_payload(
        cve_id="  cve-2026-10002  ",
    )

    response = client.post(
        "/api/v1/vulnerabilities",
        headers=auth_headers,
        json=payload,
    )

    assert response.status_code == 201
    assert response.json()["cve_id"] == "CVE-2026-10002"


def test_list_vulnerabilities(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    create_vulnerability(client, auth_headers)

    response = client.get(
        "/api/v1/vulnerabilities",
        headers=auth_headers,
    )

    assert response.status_code == 200

    body = response.json()

    assert body["total"] == 1
    assert body["page"] == 1
    assert body["size"] == 20
    assert body["pages"] == 1
    assert body["items"][0]["cve_id"] == "CVE-2026-10001"


def test_get_vulnerability(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    vulnerability = create_vulnerability(
        client,
        auth_headers,
    )

    response = client.get(
        f"/api/v1/vulnerabilities/{vulnerability['id']}",
        headers=auth_headers,
    )

    assert response.status_code == 200
    assert response.json()["id"] == vulnerability["id"]


def test_get_unknown_vulnerability_returns_404(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    response = client.get(
        ("/api/v1/vulnerabilities/3fa85f64-5717-4562-b3fc-2c963f66afa6"),
        headers=auth_headers,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Vulnerability not found"


def test_update_vulnerability(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    vulnerability = create_vulnerability(
        client,
        auth_headers,
    )

    response = client.patch(
        f"/api/v1/vulnerabilities/{vulnerability['id']}",
        headers=auth_headers,
        json={
            "severity": "high",
            "epss_score": 0.75,
            "is_patch_available": False,
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["severity"] == "high"
    assert body["epss_score"] == 0.75
    assert body["is_patch_available"] is False


def test_vulnerability_search_and_filters(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    create_vulnerability(client, auth_headers)

    create_vulnerability(
        client,
        auth_headers,
        build_vulnerability_payload(
            cve_id="CVE-2026-10002",
            title="Medium severity database issue",
        )
        | {
            "severity": "medium",
            "cvss_v3_score": 5.5,
            "epss_score": 0.20,
            "is_cisa_kev": False,
            "is_patch_available": False,
            "vendor": "Database Vendor",
            "product": "Database Product",
        },
    )

    response = client.get(
        (
            "/api/v1/vulnerabilities"
            "?search=remote"
            "&severity=critical"
            "&is_cisa_kev=true"
            "&is_patch_available=true"
            "&minimum_cvss=9"
            "&minimum_epss=0.9"
        ),
        headers=auth_headers,
    )

    assert response.status_code == 200

    body = response.json()

    assert body["total"] == 1
    assert body["items"][0]["cve_id"] == "CVE-2026-10001"


def test_vulnerability_pagination(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    for number in range(1, 4):
        create_vulnerability(
            client,
            auth_headers,
            build_vulnerability_payload(
                cve_id=f"CVE-2026-2000{number}",
                title=f"Test vulnerability {number}",
            ),
        )

    response = client.get(
        "/api/v1/vulnerabilities?page=2&size=2",
        headers=auth_headers,
    )

    assert response.status_code == 200

    body = response.json()

    assert body["total"] == 3
    assert body["page"] == 2
    assert body["size"] == 2
    assert body["pages"] == 2
    assert len(body["items"]) == 1


def test_delete_vulnerability(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    vulnerability = create_vulnerability(
        client,
        auth_headers,
    )

    delete_response = client.delete(
        f"/api/v1/vulnerabilities/{vulnerability['id']}",
        headers=auth_headers,
    )

    get_response = client.get(
        f"/api/v1/vulnerabilities/{vulnerability['id']}",
        headers=auth_headers,
    )

    assert delete_response.status_code == 204
    assert delete_response.content == b""
    assert get_response.status_code == 404


def test_invalid_vulnerability_uuid_returns_422(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    response = client.get(
        "/api/v1/vulnerabilities/not-a-valid-uuid",
        headers=auth_headers,
    )

    assert response.status_code == 422


def test_invalid_cvss_score_is_rejected(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    payload = build_vulnerability_payload()
    payload["cvss_v3_score"] = 11.0

    response = client.post(
        "/api/v1/vulnerabilities",
        headers=auth_headers,
        json=payload,
    )

    assert response.status_code == 422


def test_invalid_epss_score_is_rejected(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    payload = build_vulnerability_payload()
    payload["epss_score"] = 1.5

    response = client.post(
        "/api/v1/vulnerabilities",
        headers=auth_headers,
        json=payload,
    )

    assert response.status_code == 422
