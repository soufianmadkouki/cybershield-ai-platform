from datetime import UTC, datetime

import pytest

from app.commands.sync_epss import (
    build_parser,
    normalize_requested_cves,
    parse_date,
    validate_arguments,
)


def test_parse_date_accepts_iso_date() -> None:
    parsed = parse_date("2026-08-05")

    assert parsed == datetime(
        2026,
        8,
        5,
        tzinfo=UTC,
    )


def test_parse_date_accepts_timezone_datetime() -> None:
    parsed = parse_date(
        "2026-08-05T14:30:00+02:00",
    )

    assert parsed == datetime(
        2026,
        8,
        5,
        12,
        30,
        tzinfo=UTC,
    )


def test_parse_date_rejects_invalid_value() -> None:
    with pytest.raises(
        Exception,
        match="Expected ISO date or datetime",
    ):
        parse_date("invalid-date")


def test_normalize_requested_cves() -> None:
    cve_ids = normalize_requested_cves(
        [
            " cve-2026-63077 ",
            "CVE-2026-18556,CVE-2026-63077",
        ]
    )

    assert cve_ids == [
        "CVE-2026-63077",
        "CVE-2026-18556",
    ]


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
