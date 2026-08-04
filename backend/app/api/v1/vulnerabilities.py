from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Response, status

from app.api.dependencies import CurrentTenant, DatabaseSession
from app.models import (
    MembershipRole,
    VulnerabilitySeverity,
    VulnerabilitySource,
    VulnerabilityStatus,
)
from app.schemas.vulnerability import (
    AssetVulnerabilityCreate,
    AssetVulnerabilityListResponse,
    AssetVulnerabilityResponse,
    AssetVulnerabilityUpdate,
    VulnerabilityCreate,
    VulnerabilityListResponse,
    VulnerabilityResponse,
    VulnerabilityUpdate,
)
from app.services.vulnerability import (
    AssetFindingConflictError,
    AssetFindingNotFoundError,
    AssetTenantMismatchError,
    VulnerabilityConflictError,
    VulnerabilityNotFoundError,
    create_asset_finding,
    create_vulnerability,
    delete_asset_finding,
    delete_vulnerability,
    get_asset_finding,
    get_vulnerability,
    list_asset_findings,
    list_vulnerabilities,
    update_asset_finding,
    update_vulnerability,
)

router = APIRouter(
    prefix="/vulnerabilities",
    tags=["Vulnerabilities"],
)

WRITE_ROLES = {
    MembershipRole.OWNER,
    MembershipRole.ADMIN,
    MembershipRole.ANALYST,
    MembershipRole.OPERATOR,
}


def require_write_access(tenant: CurrentTenant) -> None:
    if tenant.membership.role not in WRITE_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This role cannot modify vulnerabilities",
        )


@router.post(
    "",
    response_model=VulnerabilityResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_vulnerability_endpoint(
    payload: VulnerabilityCreate,
    database: DatabaseSession,
    tenant: CurrentTenant,
) -> VulnerabilityResponse:
    require_write_access(tenant)

    try:
        vulnerability = create_vulnerability(
            database,
            payload,
        )
    except VulnerabilityConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    return VulnerabilityResponse.model_validate(vulnerability)


@router.get(
    "",
    response_model=VulnerabilityListResponse,
)
def list_vulnerabilities_endpoint(
    database: DatabaseSession,
    _: CurrentTenant,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=100),
    search: str | None = Query(
        default=None,
        min_length=1,
        max_length=200,
    ),
    severity: VulnerabilitySeverity | None = None,
    source: VulnerabilitySource | None = None,
    is_cisa_kev: bool | None = None,
    is_patch_available: bool | None = None,
    minimum_cvss: float | None = Query(default=None, ge=0, le=10),
    minimum_epss: float | None = Query(default=None, ge=0, le=1),
) -> VulnerabilityListResponse:
    result = list_vulnerabilities(
        database,
        page=page,
        size=size,
        search=search,
        severity=severity,
        source=source,
        is_cisa_kev=is_cisa_kev,
        is_patch_available=is_patch_available,
        minimum_cvss=minimum_cvss,
        minimum_epss=minimum_epss,
    )

    return VulnerabilityListResponse(
        items=[VulnerabilityResponse.model_validate(item) for item in result.items],
        total=result.total,
        page=result.page,
        size=result.size,
        pages=result.pages,
    )


@router.post(
    "/findings",
    response_model=AssetVulnerabilityResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_asset_finding_endpoint(
    payload: AssetVulnerabilityCreate,
    database: DatabaseSession,
    tenant: CurrentTenant,
) -> AssetVulnerabilityResponse:
    require_write_access(tenant)

    try:
        finding = create_asset_finding(
            database,
            tenant.organization.id,
            payload,
        )
    except VulnerabilityNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except AssetTenantMismatchError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except AssetFindingConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    return AssetVulnerabilityResponse.model_validate(finding)


@router.get(
    "/findings",
    response_model=AssetVulnerabilityListResponse,
)
def list_asset_findings_endpoint(
    database: DatabaseSession,
    tenant: CurrentTenant,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=100),
    asset_id: UUID | None = None,
    vulnerability_id: UUID | None = None,
    finding_status: VulnerabilityStatus | None = None,
    minimum_risk_score: float | None = Query(
        default=None,
        ge=0,
        le=100,
    ),
) -> AssetVulnerabilityListResponse:
    result = list_asset_findings(
        database,
        tenant.organization.id,
        page=page,
        size=size,
        asset_id=asset_id,
        vulnerability_id=vulnerability_id,
        finding_status=finding_status,
        minimum_risk_score=minimum_risk_score,
    )

    return AssetVulnerabilityListResponse(
        items=[AssetVulnerabilityResponse.model_validate(item) for item in result.items],
        total=result.total,
        page=result.page,
        size=result.size,
        pages=result.pages,
    )


@router.get(
    "/findings/{finding_id}",
    response_model=AssetVulnerabilityResponse,
)
def get_asset_finding_endpoint(
    finding_id: UUID,
    database: DatabaseSession,
    tenant: CurrentTenant,
) -> AssetVulnerabilityResponse:
    try:
        finding = get_asset_finding(
            database,
            tenant.organization.id,
            finding_id,
        )
    except AssetFindingNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    return AssetVulnerabilityResponse.model_validate(finding)


@router.patch(
    "/findings/{finding_id}",
    response_model=AssetVulnerabilityResponse,
)
def update_asset_finding_endpoint(
    finding_id: UUID,
    payload: AssetVulnerabilityUpdate,
    database: DatabaseSession,
    tenant: CurrentTenant,
) -> AssetVulnerabilityResponse:
    require_write_access(tenant)

    try:
        finding = update_asset_finding(
            database,
            tenant.organization.id,
            finding_id,
            payload,
        )
    except AssetFindingNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    return AssetVulnerabilityResponse.model_validate(finding)


@router.delete(
    "/findings/{finding_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_asset_finding_endpoint(
    finding_id: UUID,
    database: DatabaseSession,
    tenant: CurrentTenant,
) -> Response:
    require_write_access(tenant)

    try:
        delete_asset_finding(
            database,
            tenant.organization.id,
            finding_id,
        )
    except AssetFindingNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/{vulnerability_id}",
    response_model=VulnerabilityResponse,
)
def get_vulnerability_endpoint(
    vulnerability_id: UUID,
    database: DatabaseSession,
    _: CurrentTenant,
) -> VulnerabilityResponse:
    try:
        vulnerability = get_vulnerability(
            database,
            vulnerability_id,
        )
    except VulnerabilityNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    return VulnerabilityResponse.model_validate(vulnerability)


@router.patch(
    "/{vulnerability_id}",
    response_model=VulnerabilityResponse,
)
def update_vulnerability_endpoint(
    vulnerability_id: UUID,
    payload: VulnerabilityUpdate,
    database: DatabaseSession,
    tenant: CurrentTenant,
) -> VulnerabilityResponse:
    require_write_access(tenant)

    try:
        vulnerability = update_vulnerability(
            database,
            vulnerability_id,
            payload,
        )
    except VulnerabilityNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except VulnerabilityConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    return VulnerabilityResponse.model_validate(vulnerability)


@router.delete(
    "/{vulnerability_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_vulnerability_endpoint(
    vulnerability_id: UUID,
    database: DatabaseSession,
    tenant: CurrentTenant,
) -> Response:
    require_write_access(tenant)

    try:
        delete_vulnerability(
            database,
            vulnerability_id,
        )
    except VulnerabilityNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    return Response(status_code=status.HTTP_204_NO_CONTENT)
