from uuid import uuid4

import pytest
from jwt.exceptions import InvalidTokenError

from app.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)


def test_password_hash_is_not_plaintext() -> None:
    password = "Very-Strong-Test-Password-2026"

    hashed_password = hash_password(password)

    assert hashed_password != password
    assert verify_password(password, hashed_password)


def test_incorrect_password_is_rejected() -> None:
    hashed_password = hash_password("Very-Strong-Test-Password-2026")

    assert not verify_password(
        "Incorrect-Password-2026",
        hashed_password,
    )


def test_access_token_contains_subject() -> None:
    user_id = str(uuid4())

    token = create_access_token(subject=user_id)
    payload = decode_access_token(token)

    assert payload["sub"] == user_id
    assert payload["type"] == "access"


def test_invalid_access_token_is_rejected() -> None:
    with pytest.raises(InvalidTokenError):
        decode_access_token("this-is-not-a-valid-token")
