from typing import Any

from fastapi.testclient import TestClient


def test_register_organization_owner(
    client: TestClient,
    registration_payload: dict[str, Any],
) -> None:
    response = client.post(
        "/api/v1/auth/register",
        json=registration_payload,
    )

    assert response.status_code == 201

    payload = response.json()

    assert payload["user"]["email"] == registration_payload["email"]
    assert payload["user"]["first_name"] == registration_payload["first_name"]
    assert payload["user"]["last_name"] == registration_payload["last_name"]

    assert payload["organization"]["name"] == registration_payload["organization_name"]
    assert payload["organization"]["slug"] == registration_payload["organization_slug"]

    assert payload["role"] == "owner"
    assert payload["token_type"] == "bearer"
    assert payload["access_token"]
    assert payload["expires_in"] == 1800


def test_registration_normalizes_email_and_slug(
    client: TestClient,
    registration_payload: dict[str, Any],
) -> None:
    registration_payload["email"] = "  OWNER@CYBERSHIELD.EXAMPLE.COM  "
    registration_payload["organization_slug"] = "  CyberShield-Test  "

    response = client.post(
        "/api/v1/auth/register",
        json=registration_payload,
    )

    assert response.status_code == 201

    payload = response.json()

    assert payload["user"]["email"] == "owner@cybershield.example.com"
    assert payload["organization"]["slug"] == "cybershield-test"


def test_duplicate_email_is_rejected(
    client: TestClient,
    registration_payload: dict[str, Any],
) -> None:
    first_response = client.post(
        "/api/v1/auth/register",
        json=registration_payload,
    )

    second_payload = {
        **registration_payload,
        "organization_name": "Second Organization",
        "organization_slug": "second-organization",
    }

    second_response = client.post(
        "/api/v1/auth/register",
        json=second_payload,
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 409
    assert second_response.json()["detail"] == ("A user with this email already exists")


def test_duplicate_organization_slug_is_rejected(
    client: TestClient,
    registration_payload: dict[str, Any],
) -> None:
    first_response = client.post(
        "/api/v1/auth/register",
        json=registration_payload,
    )

    second_payload = {
        **registration_payload,
        "email": "second-owner@cybershield.example.com",
    }

    second_response = client.post(
        "/api/v1/auth/register",
        json=second_payload,
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 409
    assert second_response.json()["detail"] == ("An organization with this slug already exists")


def test_login_returns_access_token(
    client: TestClient,
    registered_owner: dict[str, Any],
    registration_payload: dict[str, Any],
) -> None:
    response = client.post(
        "/api/v1/auth/login",
        data={
            "username": registration_payload["email"],
            "password": registration_payload["password"],
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["token_type"] == "bearer"
    assert payload["access_token"]
    assert payload["expires_in"] == 1800


def test_invalid_password_is_rejected(
    client: TestClient,
    registered_owner: dict[str, Any],
    registration_payload: dict[str, Any],
) -> None:
    response = client.post(
        "/api/v1/auth/login",
        data={
            "username": registration_payload["email"],
            "password": "Incorrect-Password-2026",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password"


def test_current_user_returns_authenticated_identity(
    client: TestClient,
    access_token: str,
    registration_payload: dict[str, Any],
) -> None:
    response = client.get(
        "/api/v1/auth/me",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["email"] == registration_payload["email"]
    assert payload["first_name"] == registration_payload["first_name"]
    assert payload["last_name"] == registration_payload["last_name"]
    assert payload["is_active"] is True


def test_current_user_requires_authentication(
    client: TestClient,
) -> None:
    response = client.get("/api/v1/auth/me")

    assert response.status_code == 401


def test_invalid_token_is_rejected(
    client: TestClient,
) -> None:
    response = client.get(
        "/api/v1/auth/me",
        headers={
            "Authorization": "Bearer invalid-token",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"
