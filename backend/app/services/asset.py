from dataclasses import dataclass
from math import ceil
from uuid import UUID

from sqlalchemy import Select, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import (
    Asset,
    AssetCriticality,
    AssetEnvironment,
    AssetStatus,
    AssetType,
)
from app.schemas.asset import AssetCreate, AssetUpdate


class AssetConflictError(Exception):
    pass


class AssetNotFoundError(Exception):
    pass


@dataclass(frozen=True)
class AssetPage:
    items: list[Asset]
    total: int
    page: int
    size: int
    pages: int


def _prepare_asset_data(
    data: dict[str, object],
) -> dict[str, object]:
    ip_address = data.get("ip_address")

    if ip_address is not None:
        data["ip_address"] = str(ip_address)

    return data


def create_asset(
    database: Session,
    organization_id: UUID,
    payload: AssetCreate,
) -> Asset:
    values = _prepare_asset_data(
        payload.model_dump(),
    )

    asset = Asset(
        organization_id=organization_id,
        **values,
    )

    database.add(asset)

    try:
        database.commit()
    except IntegrityError as exc:
        database.rollback()
        raise AssetConflictError(
            "An asset with this hostname already exists in the organization"
        ) from exc

    database.refresh(asset)
    return asset


def get_asset(
    database: Session,
    organization_id: UUID,
    asset_id: UUID,
) -> Asset:
    asset = database.scalar(
        select(Asset).where(
            Asset.id == asset_id,
            Asset.organization_id == organization_id,
        )
    )

    if asset is None:
        raise AssetNotFoundError("Asset not found")

    return asset


def list_assets(
    database: Session,
    organization_id: UUID,
    *,
    page: int,
    size: int,
    search: str | None = None,
    asset_type: AssetType | None = None,
    environment: AssetEnvironment | None = None,
    criticality: AssetCriticality | None = None,
    asset_status: AssetStatus | None = None,
) -> AssetPage:
    filters = [Asset.organization_id == organization_id]

    if search:
        pattern = f"%{search.strip()}%"

        filters.append(
            or_(
                Asset.name.ilike(pattern),
                Asset.hostname.ilike(pattern),
                Asset.ip_address.ilike(pattern),
                Asset.owner.ilike(pattern),
                Asset.external_id.ilike(pattern),
            )
        )

    if asset_type is not None:
        filters.append(Asset.asset_type == asset_type)

    if environment is not None:
        filters.append(Asset.environment == environment)

    if criticality is not None:
        filters.append(Asset.criticality == criticality)

    if asset_status is not None:
        filters.append(Asset.status == asset_status)

    count_statement = select(func.count()).select_from(Asset).where(*filters)

    total = database.scalar(count_statement) or 0

    statement: Select[tuple[Asset]] = (
        select(Asset)
        .where(*filters)
        .order_by(
            Asset.criticality.asc(),
            Asset.name.asc(),
        )
        .offset((page - 1) * size)
        .limit(size)
    )

    items = list(database.scalars(statement).all())
    pages = ceil(total / size) if total else 0

    return AssetPage(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


def update_asset(
    database: Session,
    organization_id: UUID,
    asset_id: UUID,
    payload: AssetUpdate,
) -> Asset:
    asset = get_asset(
        database,
        organization_id,
        asset_id,
    )

    values = _prepare_asset_data(
        payload.model_dump(exclude_unset=True),
    )

    for field, value in values.items():
        setattr(asset, field, value)

    try:
        database.commit()
    except IntegrityError as exc:
        database.rollback()
        raise AssetConflictError(
            "An asset with this hostname already exists in the organization"
        ) from exc

    database.refresh(asset)
    return asset


def delete_asset(
    database: Session,
    organization_id: UUID,
    asset_id: UUID,
) -> None:
    asset = get_asset(
        database,
        organization_id,
        asset_id,
    )

    database.delete(asset)
    database.commit()
