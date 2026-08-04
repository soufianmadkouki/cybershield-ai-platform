from typing import Annotated
from uuid import UUID

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
    Response,
    status,
)

from app.api.dependencies import CurrentTenant, DatabaseSession
from app.models import (
    AssetCriticality,
    AssetEnvironment,
    AssetStatus,
    AssetType,
    MembershipRole,
)
from app.schemas.asset import (
    AssetCreate,
    AssetListResponse,
    AssetResponse,
    AssetUpdate,
)
from app.services.asset import (
    AssetConflictError,
    AssetNotFoundError,
    create_asset,
    delete_asset,
    get_asset,
    list_assets,
    update_asset,
)

router = APIRouter(
    prefix="/assets",
    tags=["Assets"],
)

PageParameter = Annotated[int, Query(ge=1)]
SizeParameter = Annotated[int, Query(ge=1, le=100)]
SearchParameter = Annotated[
    str | None,
    Query(min_length=1, max_length=200),
]

WRITE_ROLES = {
    MembershipRole.OWNER,
    MembershipRole.ADMIN,
    MembershipRole.OPERATOR,
}


def require_write_access(tenant: CurrentTenant) -> None:
    if tenant.membership.role not in WRITE_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This role cannot modify assets",
        )


@router.post(
    "",
    response_model=AssetResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_asset_endpoint(
    payload: AssetCreate,
    database: DatabaseSession,
    tenant: CurrentTenant,
) -> AssetResponse:
    require_write_access(tenant)

    try:
        asset = create_asset(
            database,
            tenant.organization.id,
            payload,
        )
    except AssetConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    return AssetResponse.model_validate(asset)


@router.get(
    "",
    response_model=AssetListResponse,
)
def list_assets_endpoint(
    database: DatabaseSession,
    tenant: CurrentTenant,
    page: PageParameter = 1,
    size: SizeParameter = 20,
    search: SearchParameter = None,
    asset_type: AssetType | None = None,
    environment: AssetEnvironment | None = None,
    criticality: AssetCriticality | None = None,
    asset_status: Annotated[
        AssetStatus | None,
        Query(alias="status"),
    ] = None,
) -> AssetListResponse:
    result = list_assets(
        database,
        tenant.organization.id,
        page=page,
        size=size,
        search=search,
        asset_type=asset_type,
        environment=environment,
        criticality=criticality,
        asset_status=asset_status,
    )

    return AssetListResponse(
        items=[AssetResponse.model_validate(asset) for asset in result.items],
        total=result.total,
        page=result.page,
        size=result.size,
        pages=result.pages,
    )


@router.get(
    "/{asset_id}",
    response_model=AssetResponse,
)
def get_asset_endpoint(
    asset_id: UUID,
    database: DatabaseSession,
    tenant: CurrentTenant,
) -> AssetResponse:
    try:
        asset = get_asset(
            database,
            tenant.organization.id,
            asset_id,
        )
    except AssetNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    return AssetResponse.model_validate(asset)


@router.patch(
    "/{asset_id}",
    response_model=AssetResponse,
)
def update_asset_endpoint(
    asset_id: UUID,
    payload: AssetUpdate,
    database: DatabaseSession,
    tenant: CurrentTenant,
) -> AssetResponse:
    require_write_access(tenant)

    try:
        asset = update_asset(
            database,
            tenant.organization.id,
            asset_id,
            payload,
        )
    except AssetNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except AssetConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    return AssetResponse.model_validate(asset)


@router.delete(
    "/{asset_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_asset_endpoint(
    asset_id: UUID,
    database: DatabaseSession,
    tenant: CurrentTenant,
) -> Response:
    require_write_access(tenant)

    try:
        delete_asset(
            database,
            tenant.organization.id,
            asset_id,
        )
    except AssetNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    return Response(status_code=status.HTTP_204_NO_CONTENT)
