from datetime import UTC, datetime

import pytest

from app.commands.sync_cisa_kev import (
    build_parser,
    parse_since,
    validate_arguments,
)


def test_parse_since_accepts_date() -> None:
    parsed = parse_since("2026-08-01")

    assert parsed == datetime(
        2026,
        8,
        1,
        tzinfo=UTC,
    )


def test_parse_since_accepts_timezone_aware_datetime() -> None:
    parsed = parse_since(
        "2026-08-01T12:30:00+02:00",
    )

    assert parsed == datetime(
        2026,
        8,
        1,
        10,
        30,
        tzinfo=UTC,
    )


def test_parse_since_rejects_invalid_value() -> None:
    with pytest.raises(
        Exception,
        match="Expected ISO date or datetime",
    ):
        parse_since("not-a-date")


def test_validate_arguments_rejects_zero_limit() -> None:
    parser = build_parser()
    arguments = parser.parse_args(
        [
            "--limit",
            "0",
        ]
    )

    with pytest.raises(SystemExit):
        validate_arguments(
            parser,
            arguments,
        )
