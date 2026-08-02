from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.security import hash_password, verify_password
from app.models import Membership, MembershipRole, Organization, User
from app.schemas.auth import RegisterRequest


class IdentityConflictError(Exception):
    pass


class InvalidCredentialsError(Exception):
    pass


@dataclass
class RegistrationResult:
    user: User
    organization: Organization
    membership: Membership


def normalize_email(email: str) -> str:
    return email.strip().lower()


def register_organization_owner(
    database: Session,
    payload: RegisterRequest,
) -> RegistrationResult:
    email = normalize_email(str(payload.email))
    slug = payload.organization_slug.strip().lower()

    existing_user = database.scalar(select(User).where(User.email == email))
    if existing_user is not None:
        raise IdentityConflictError("A user with this email already exists")

    existing_organization = database.scalar(select(Organization).where(Organization.slug == slug))
    if existing_organization is not None:
        raise IdentityConflictError("An organization with this slug already exists")

    organization = Organization(
        name=payload.organization_name.strip(),
        slug=slug,
    )

    user = User(
        email=email,
        password_hash=hash_password(payload.password),
        first_name=payload.first_name,
        last_name=payload.last_name,
    )

    membership = Membership(
        organization=organization,
        user=user,
        role=MembershipRole.OWNER,
    )

    database.add_all([organization, user, membership])

    try:
        database.commit()
    except IntegrityError as exc:
        database.rollback()
        raise IdentityConflictError("The user or organization already exists") from exc

    database.refresh(organization)
    database.refresh(user)
    database.refresh(membership)

    return RegistrationResult(
        user=user,
        organization=organization,
        membership=membership,
    )


def authenticate_user(
    database: Session,
    email: str,
    password: str,
) -> User:
    normalized_email = normalize_email(email)

    user = database.scalar(select(User).where(User.email == normalized_email))

    if user is None or not verify_password(
        password,
        user.password_hash,
    ):
        raise InvalidCredentialsError("Invalid email or password")

    if not user.is_active:
        raise InvalidCredentialsError("User account is inactive")

    return user
