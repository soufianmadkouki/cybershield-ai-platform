import argparse
import json
import sys
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from app.db.session import SessionLocal
from app.integrations.threat_intelligence.epss import (
    EpssProvider,
    EpssProviderError,
)
from app.models import Vulnerability
from app.services.vulnerability_ingestion import (
    ingest_threat_intelligence_provider,
)


def parse_date(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "Expected ISO date or datetime, for example 2026-08-05"
        ) from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)

    return parsed.astimezone(UTC)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=("Enrich CyberShield vulnerabilities with FIRST EPSS scores."),
    )

    parser.add_argument(
        "--cve",
        action="append",
        dest="cve_ids",
        help=(
            "CVE ID to enrich. May be supplied multiple times. "
            "If omitted, CVEs are selected from the CyberShield database."
        ),
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help=(
            "Maximum number of CyberShield CVEs to enrich when --cve is not provided. Default: 100."
        ),
    )

    parser.add_argument(
        "--date",
        type=parse_date,
        default=None,
        help="Retrieve the EPSS score for a specific historical date.",
    )

    parser.add_argument(
        "--missing-only",
        action="store_true",
        help=("Select only vulnerabilities that do not currently have an EPSS score."),
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch EPSS scores without writing changes to PostgreSQL.",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the result as JSON.",
    )

    return parser


def validate_arguments(
    parser: argparse.ArgumentParser,
    arguments: argparse.Namespace,
) -> None:
    if arguments.limit < 1:
        parser.error("--limit must be greater than or equal to 1")


def normalize_requested_cves(
    values: list[str] | None,
) -> list[str]:
    if not values:
        return []

    normalized: list[str] = []
    seen: set[str] = set()

    for raw_value in values:
        for item in raw_value.split(","):
            cve_id = item.strip().upper()

            if not cve_id or cve_id in seen:
                continue

            seen.add(cve_id)
            normalized.append(cve_id)

    return normalized


def select_database_cves(
    *,
    limit: int,
    missing_only: bool,
) -> list[str]:
    with SessionLocal() as database:
        statement = select(Vulnerability.cve_id).order_by(
            Vulnerability.updated_at.desc(),
        )

        if missing_only:
            statement = statement.where(
                Vulnerability.epss_score.is_(None),
            )

        statement = statement.limit(limit)

        cve_ids = database.scalars(statement).all()

        return [cve_id for cve_id in cve_ids if cve_id is not None]


def resolve_cve_ids(
    arguments: argparse.Namespace,
) -> list[str]:
    explicit_cves = normalize_requested_cves(arguments.cve_ids)

    if explicit_cves:
        return explicit_cves

    return select_database_cves(
        limit=arguments.limit,
        missing_only=arguments.missing_only,
    )


def build_dry_run_summary(
    provider: EpssProvider,
    *,
    score_date: datetime | None,
) -> dict[str, Any]:
    raw_records = provider.fetch_records(
        since=score_date,
    )

    normalized_records = [provider.normalize_record(record) for record in raw_records]

    return {
        "provider": provider.name.value,
        "dry_run": True,
        "requested": len(provider.cve_ids),
        "fetched": len(raw_records),
        "records": [
            {
                "cve_id": record.cve_id,
                "epss_score": record.epss_score,
                "epss_percentile": record.epss_percentile,
                "score_date": record.provider_metadata.get("score_date"),
            }
            for record in normalized_records
        ],
    }


def build_database_summary(
    provider: EpssProvider,
    *,
    score_date: datetime | None,
) -> dict[str, Any]:
    with SessionLocal() as database:
        summary = ingest_threat_intelligence_provider(
            database,
            provider,
            since=score_date,
        )

        cve_ids = [result.cve_id for result in summary.results if result.cve_id is not None]

        enriched = 0

        if cve_ids:
            enriched = len(
                database.scalars(
                    select(Vulnerability.id).where(
                        Vulnerability.cve_id.in_(cve_ids),
                        Vulnerability.epss_score.is_not(None),
                    )
                ).all()
            )

        return {
            **summary.model_dump(mode="json"),
            "dry_run": False,
            "requested": len(provider.cve_ids),
            "enriched": enriched,
        }


def print_human_summary(summary: dict[str, Any]) -> None:
    print("FIRST EPSS synchronization")
    print(f"Provider:   {summary['provider']}")
    print(f"Dry run:    {summary['dry_run']}")
    print(f"Requested:  {summary['requested']}")
    print(f"Fetched:    {summary['fetched']}")

    if summary["dry_run"]:
        for record in summary["records"]:
            print(
                f"- {record['cve_id']}: "
                f"EPSS={record['epss_score']} "
                f"percentile={record['epss_percentile']} "
                f"date={record['score_date']}"
            )

        return

    print(f"Created:    {summary['created']}")
    print(f"Updated:    {summary['updated']}")
    print(f"Skipped:    {summary['skipped']}")
    print(f"Failed:     {summary['failed']}")
    print(f"Enriched:   {summary['enriched']}")

    for result in summary["results"]:
        detail = f" — {result['detail']}" if result["detail"] else ""

        print(f"- {result['action']}: {result['cve_id'] or result['provider_record_id']}{detail}")


def main() -> int:
    parser = build_parser()
    arguments = parser.parse_args()

    validate_arguments(parser, arguments)

    cve_ids = resolve_cve_ids(arguments)

    if not cve_ids:
        print(
            "No CVEs are available for EPSS enrichment.",
            file=sys.stderr,
        )
        return 0

    provider = EpssProvider(cve_ids)

    try:
        if arguments.dry_run:
            summary = build_dry_run_summary(
                provider,
                score_date=arguments.date,
            )
        else:
            summary = build_database_summary(
                provider,
                score_date=arguments.date,
            )
    except EpssProviderError as exc:
        print(
            f"EPSS synchronization failed: {exc}",
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
