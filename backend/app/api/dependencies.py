from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jwt.exceptions import InvalidTokenError
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.security import decode_access_token
from app.db.session import get_db
from app.models import Membership, Organization, User

DatabaseSession = Annotated[Session, Depends(get_db)]

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/auth/login",
)

AccessToken = Annotated[str, Depends(oauth2_scheme)]
OrganizationHeader = Annotated[
    UUID | None,
    Header(alias="X-Organization-ID"),
]


def get_current_user(
    token: AccessToken,
    database: DatabaseSession,
) -> User:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_access_token(token)
        subject = payload.get("sub")
        token_type = payload.get("type")

        if not isinstance(subject, str) or token_type != "access":
            raise credentials_error

        user_id = UUID(subject)
    except (InvalidTokenError, ValueError) as exc:
        raise credentials_error from exc

    user = database.get(User, user_id)

    if user is None or not user.is_active:
        raise credentials_error

    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


@dataclass(frozen=True)
class TenantContext:
    user: User
    membership: Membership
    organization: Organization


def get_current_tenant(
    user: CurrentUser,
    database: DatabaseSession,
    organization_id: OrganizationHeader = None,
) -> TenantContext:
    statement = (
        select(Membership)
        .options(selectinload(Membership.organization))
        .where(
            Membership.user_id == user.id,
            Membership.is_active.is_(True),
        )
    )

    memberships = list(database.scalars(statement).all())

    if not memberships:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User has no active organization membership",
        )

    if organization_id is not None:
        selected_membership = next(
            (
                membership
                for membership in memberships
                if membership.organization_id == organization_id
            ),
            None,
        )

        if selected_membership is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User does not belong to this organization",
            )
    elif len(memberships) == 1:
        selected_membership = memberships[0]
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=("Multiple organizations are available. Provide the X-Organization-ID header."),
        )

    organization = selected_membership.organization

    if organization is None or not organization.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization is inactive or unavailable",
        )

    return TenantContext(
        user=user,
        membership=selected_membership,
        organization=organization,
    )


CurrentTenant = Annotated[TenantContext, Depends(get_current_tenant)]
