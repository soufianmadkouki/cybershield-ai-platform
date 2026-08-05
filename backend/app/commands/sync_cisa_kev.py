import argparse
import json
import sys
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from app.db.session import SessionLocal
from app.integrations.threat_intelligence.cisa_kev import (
    CisaKevProvider,
    CisaKevProviderError,
)
from app.models import Vulnerability
from app.services.vulnerability_ingestion import (
    ingest_threat_intelligence_provider,
)


def parse_since(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "Expected ISO date or datetime, for example 2026-08-01"
        ) from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)

    return parsed.astimezone(UTC)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Synchronize the CISA Known Exploited Vulnerabilities catalog into CyberShield."
        ),
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of CISA KEV records to process.",
    )

    parser.add_argument(
        "--since",
        type=parse_since,
        default=None,
        help=("Only process records added on or after this ISO date or datetime."),
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=("Fetch and normalize records without writing changes to PostgreSQL."),
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the synchronization summary as JSON.",
    )

    return parser


def validate_arguments(
    parser: argparse.ArgumentParser,
    arguments: argparse.Namespace,
) -> None:
    if arguments.limit is not None and arguments.limit < 1:
        parser.error("--limit must be greater than or equal to 1")


def build_dry_run_summary(
    provider: CisaKevProvider,
    *,
    since: datetime | None,
    limit: int | None,
) -> dict[str, Any]:
    raw_records = provider.fetch_records(
        since=since,
        limit=limit,
    )

    normalized_records = [provider.normalize_record(record) for record in raw_records]

    return {
        "provider": provider.name.value,
        "dry_run": True,
        "fetched": len(raw_records),
        "records": [
            {
                "provider_record_id": record.provider_record_id,
                "cve_id": record.cve_id,
                "title": record.title,
                "vendor": record.vendor,
                "product": record.product,
                "is_cisa_kev": record.is_cisa_kev,
            }
            for record in normalized_records
        ],
    }


def build_database_summary(
    provider: CisaKevProvider,
    *,
    since: datetime | None,
    limit: int | None,
) -> dict[str, Any]:
    with SessionLocal() as database:
        summary = ingest_threat_intelligence_provider(
            database,
            provider,
            since=since,
            limit=limit,
        )

        cve_ids = [result.cve_id for result in summary.results if result.cve_id is not None]

        persisted = 0

        if cve_ids:
            persisted = len(
                database.scalars(
                    select(Vulnerability.id).where(
                        Vulnerability.cve_id.in_(cve_ids),
                    )
                ).all()
            )

        return {
            **summary.model_dump(mode="json"),
            "dry_run": False,
            "persisted": persisted,
        }


def print_human_summary(summary: dict[str, Any]) -> None:
    print("CISA KEV synchronization")
    print(f"Provider:  {summary['provider']}")
    print(f"Dry run:   {summary['dry_run']}")
    print(f"Fetched:   {summary['fetched']}")

    if summary["dry_run"]:
        for record in summary["records"]:
            print(f"- {record['cve_id']}: {record['title'] or 'Untitled vulnerability'}")

        return

    print(f"Created:   {summary['created']}")
    print(f"Updated:   {summary['updated']}")
    print(f"Skipped:   {summary['skipped']}")
    print(f"Failed:    {summary['failed']}")
    print(f"Persisted: {summary['persisted']}")

    for result in summary["results"]:
        detail = f" — {result['detail']}" if result["detail"] else ""

        print(f"- {result['action']}: {result['cve_id'] or result['provider_record_id']}{detail}")


def main() -> int:
    parser = build_parser()
    arguments = parser.parse_args()

    validate_arguments(
        parser,
        arguments,
    )

    provider = CisaKevProvider()

    try:
        if arguments.dry_run:
            summary = build_dry_run_summary(
                provider,
                since=arguments.since,
                limit=arguments.limit,
            )
        else:
            summary = build_database_summary(
                provider,
                since=arguments.since,
                limit=arguments.limit,
            )
    except CisaKevProviderError as exc:
        print(
            f"CISA KEV synchronization failed: {exc}",
            file=sys.stderr,
        )
        return 1
    finally:
        provider.close()

    if arguments.json:
        print(
            json.dumps(
                summary,
                indent=2,
                default=str,
            )
        )
    else:
        print_human_summary(summary)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
