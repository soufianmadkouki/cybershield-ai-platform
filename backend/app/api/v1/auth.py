from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from app.api.dependencies import CurrentUser, DatabaseSession
from app.core.config import get_settings
from app.core.security import create_access_token
from app.schemas.auth import (
    OrganizationResponse,
    RegisterRequest,
    RegistrationResponse,
    TokenResponse,
    UserResponse,
)
from app.services.auth import (
    IdentityConflictError,
    InvalidCredentialsError,
    authenticate_user,
    register_organization_owner,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])

OAuth2LoginForm = Annotated[
    OAuth2PasswordRequestForm,
    Depends(),
]


@router.post(
    "/register",
    response_model=RegistrationResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    payload: RegisterRequest,
    database: DatabaseSession,
) -> RegistrationResponse:
    try:
        result = register_organization_owner(database, payload)
    except IdentityConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    settings = get_settings()

    access_token = create_access_token(
        subject=str(result.user.id),
        additional_claims={
            "organization_id": str(result.organization.id),
            "role": result.membership.role.value,
        },
    )

    return RegistrationResponse(
        user=UserResponse.model_validate(result.user),
        organization=OrganizationResponse.model_validate(result.organization),
        role=result.membership.role.value,
        access_token=access_token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post(
    "/login",
    response_model=TokenResponse,
)
def login(
    form_data: OAuth2LoginForm,
    database: DatabaseSession,
) -> TokenResponse:
    try:
        user = authenticate_user(
            database,
            email=form_data.username,
            password=form_data.password,
        )
    except InvalidCredentialsError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    settings = get_settings()

    access_token = create_access_token(
        subject=str(user.id),
    )

    return TokenResponse(
        access_token=access_token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.get(
    "/me",
    response_model=UserResponse,
)
def current_user(user: CurrentUser) -> UserResponse:
    return UserResponse.model_validate(user)
