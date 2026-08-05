import os
from collections.abc import Generator
from pathlib import Path
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from alembic import command
from alembic.config import Config

# ---------------------------------------------------------------------------
# Test environment must be configured before importing application modules.
# ---------------------------------------------------------------------------

TEST_DATABASE_URL = (
    "postgresql+psycopg://"
    "cybershield:cybershield-local-dev-password"
    "@127.0.0.1:5432/cybershield_test"
)

os.environ["DATABASE_URL"] = TEST_DATABASE_URL
os.environ["JWT_SECRET_KEY"] = "cybershield-integration-test-secret"
os.environ["JWT_ALGORITHM"] = "HS256"
os.environ["ACCESS_TOKEN_EXPIRE_MINUTES"] = "30"
os.environ["APP_ENVIRONMENT"] = "test"
os.environ["DEBUG"] = "false"

from app.core.config import get_settings  # noqa: E402
from app.db.session import get_db  # noqa: E402
from app.main import app  # noqa: E402

get_settings.cache_clear()

test_engine = create_engine(
    TEST_DATABASE_URL,
    pool_pre_ping=True,
    connect_args={
        "connect_timeout": 5,
    },
)

TestSessionLocal = sessionmaker(
    bind=test_engine,
    class_=Session,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)

BACKEND_DIRECTORY = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session", autouse=True)
def migrate_test_database() -> Generator[None, None, None]:
    """Apply all Alembic migrations to the isolated test database."""
    os.environ["DATABASE_URL"] = TEST_DATABASE_URL

    alembic_config = Config(
        str(BACKEND_DIRECTORY / "alembic.ini"),
    )
    alembic_config.set_main_option(
        "script_location",
        str(BACKEND_DIRECTORY / "alembic"),
    )

    command.upgrade(
        alembic_config,
        "head",
    )

    yield

    test_engine.dispose()


@pytest.fixture(autouse=True)
def clean_test_database(
    migrate_test_database: None,
) -> Generator[None, None, None]:
    """Remove application data before and after every test."""
    truncate_database()

    yield

    truncate_database()


def truncate_database() -> None:
    table_names = [
        "asset_vulnerabilities",
        "assets",
        "memberships",
        "users",
        "organizations",
        "vulnerabilities",
    ]

    with test_engine.begin() as connection:
        connection.execute(
            text("TRUNCATE TABLE " + ", ".join(table_names) + " RESTART IDENTITY CASCADE")
        )


def override_get_db() -> Generator[Session, None, None]:
    database = TestSessionLocal()

    try:
        yield database
    finally:
        database.close()


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


@pytest.fixture
def registration_payload() -> dict[str, Any]:
    return {
        "organization_name": "CyberShield Test Organization",
        "organization_slug": "cybershield-test",
        "email": "owner@cybershield.example.com",
        "password": "Strong-Test-Password-2026",
        "first_name": "Soufian",
        "last_name": "Madkouki",
    }


@pytest.fixture
def registered_owner(
    client: TestClient,
    registration_payload: dict[str, Any],
) -> dict[str, Any]:
    response = client.post(
        "/api/v1/auth/register",
        json=registration_payload,
    )

    assert response.status_code == 201, response.text

    payload = response.json()
    return cast(dict[str, Any], payload)


@pytest.fixture
def access_token(
    client: TestClient,
    registered_owner: dict[str, Any],
    registration_payload: dict[str, Any],
) -> str:
    response = client.post(
        "/api/v1/auth/login",
        data={
            "username": registration_payload["email"],
            "password": registration_payload["password"],
        },
    )

    assert response.status_code == 200, response.text
    return str(response.json()["access_token"])


@pytest.fixture
def organization_id(
    registered_owner: dict[str, Any],
) -> str:
    return str(registered_owner["organization"]["id"])


@pytest.fixture
def auth_headers(
    access_token: str,
    organization_id: str,
) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {access_token}",
        "X-Organization-ID": organization_id,
    }


@pytest.fixture
def database_session(
    migrate_test_database: None,
) -> Generator[Session, None, None]:
    with TestSessionLocal() as database:
        yield database
