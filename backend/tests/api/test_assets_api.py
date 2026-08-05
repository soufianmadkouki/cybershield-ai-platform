from typing import Any, cast

from fastapi.testclient import TestClient


def build_asset_payload(
    *,
    name: str = "CyberShield Test Server",
    hostname: str = "cybershield-test-01",
) -> dict[str, Any]:
    return {
        "name": name,
        "hostname": hostname,
        "asset_type": "server",
        "ip_address": "10.10.10.10",
        "mac_address": "00:11:22:33:44:55",
        "operating_system": "Ubuntu",
        "operating_system_version": "24.04 LTS",
        "environment": "test",
        "criticality": "high",
        "status": "active",
        "owner": "CyberShield Engineering",
        "description": "Integration-test asset.",
        "tags": {
            "team": "engineering",
            "provider": "test",
        },
        "discovery_source": "manual",
        "external_id": "asset-test-001",
        "last_seen_at": "2026-08-05T12:00:00Z",
    }


def create_asset(
    client: TestClient,
    auth_headers: dict[str, str],
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    response = client.post(
        "/api/v1/assets",
        headers=auth_headers,
        json=payload or build_asset_payload(),
    )

    assert response.status_code == 201, response.text

    return cast(dict[str, Any], response.json())


def test_create_asset(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    payload = build_asset_payload()

    response = client.post(
        "/api/v1/assets",
        headers=auth_headers,
        json=payload,
    )

    assert response.status_code == 201

    body = response.json()

    assert body["name"] == payload["name"]
    assert body["hostname"] == payload["hostname"]
    assert body["asset_type"] == "server"
    assert body["environment"] == "test"
    assert body["criticality"] == "high"
    assert body["status"] == "active"
    assert body["organization_id"] == auth_headers["X-Organization-ID"]
    assert body["id"]


def test_create_asset_requires_authentication(
    client: TestClient,
) -> None:
    response = client.post(
        "/api/v1/assets",
        json=build_asset_payload(),
    )

    assert response.status_code == 401


def test_duplicate_hostname_is_rejected(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    first_response = client.post(
        "/api/v1/assets",
        headers=auth_headers,
        json=build_asset_payload(),
    )

    second_response = client.post(
        "/api/v1/assets",
        headers=auth_headers,
        json=build_asset_payload(
            name="Second Asset",
        ),
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 409
    assert second_response.json()["detail"] == (
        "An asset with this hostname already exists in the organization"
    )


def test_list_assets(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    create_asset(client, auth_headers)

    response = client.get(
        "/api/v1/assets",
        headers=auth_headers,
    )

    assert response.status_code == 200

    body = response.json()

    assert body["total"] == 1
    assert body["page"] == 1
    assert body["size"] == 20
    assert body["pages"] == 1
    assert len(body["items"]) == 1
    assert body["items"][0]["hostname"] == "cybershield-test-01"


def test_get_asset(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    asset = create_asset(client, auth_headers)

    response = client.get(
        f"/api/v1/assets/{asset['id']}",
        headers=auth_headers,
    )

    assert response.status_code == 200
    assert response.json()["id"] == asset["id"]


def test_get_unknown_asset_returns_404(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    response = client.get(
        "/api/v1/assets/3fa85f64-5717-4562-b3fc-2c963f66afa6",
        headers=auth_headers,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Asset not found"


def test_update_asset(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    asset = create_asset(client, auth_headers)

    response = client.patch(
        f"/api/v1/assets/{asset['id']}",
        headers=auth_headers,
        json={
            "criticality": "critical",
            "status": "inactive",
            "owner": "SOC Team",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["criticality"] == "critical"
    assert body["status"] == "inactive"
    assert body["owner"] == "SOC Team"


def test_asset_search_and_filters(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    create_asset(client, auth_headers)

    create_asset(
        client,
        auth_headers,
        build_asset_payload(
            name="CyberShield Production Database",
            hostname="cybershield-db-01",
        )
        | {
            "asset_type": "database",
            "environment": "production",
            "criticality": "critical",
            "ip_address": "10.10.10.20",
            "external_id": "asset-test-002",
        },
    )

    response = client.get(
        (
            "/api/v1/assets"
            "?search=database"
            "&asset_type=database"
            "&environment=production"
            "&criticality=critical"
            "&status=active"
        ),
        headers=auth_headers,
    )

    assert response.status_code == 200

    body = response.json()

    assert body["total"] == 1
    assert body["items"][0]["hostname"] == "cybershield-db-01"


def test_asset_pagination(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    for number in range(1, 4):
        create_asset(
            client,
            auth_headers,
            build_asset_payload(
                name=f"Asset {number}",
                hostname=f"asset-{number:02d}",
            )
            | {
                "ip_address": f"10.10.20.{number}",
                "mac_address": f"00:11:22:33:44:{number:02d}",
                "external_id": f"asset-{number:03d}",
            },
        )

    response = client.get(
        "/api/v1/assets?page=2&size=2",
        headers=auth_headers,
    )

    assert response.status_code == 200

    body = response.json()

    assert body["total"] == 3
    assert body["page"] == 2
    assert body["size"] == 2
    assert body["pages"] == 2
    assert len(body["items"]) == 1


def test_delete_asset(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    asset = create_asset(client, auth_headers)

    delete_response = client.delete(
        f"/api/v1/assets/{asset['id']}",
        headers=auth_headers,
    )

    get_response = client.get(
        f"/api/v1/assets/{asset['id']}",
        headers=auth_headers,
    )

    assert delete_response.status_code == 204
    assert delete_response.content == b""
    assert get_response.status_code == 404


def test_invalid_asset_uuid_returns_422(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    response = client.get(
        "/api/v1/assets/not-a-valid-uuid",
        headers=auth_headers,
    )

    assert response.status_code == 422


def test_invalid_ip_address_is_rejected(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    payload = build_asset_payload()
    payload["ip_address"] = "999.999.999.999"

    response = client.post(
        "/api/v1/assets",
        headers=auth_headers,
        json=payload,
    )

    assert response.status_code == 422
