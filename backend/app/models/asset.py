from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.asset_enums import (
    AssetCriticality,
    AssetDiscoverySource,
    AssetEnvironment,
    AssetStatus,
    AssetType,
)


class Asset(
    UUIDPrimaryKeyMixin,
    TimestampMixin,
    Base,
):
    __tablename__ = "assets"

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "hostname",
            name="uq_assets_organization_hostname",
        ),
        Index(
            "ix_assets_organization_status",
            "organization_id",
            "status",
        ),
        Index(
            "ix_assets_organization_type",
            "organization_id",
            "asset_type",
        ),
    )

    organization_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey(
            "organizations.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    name: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
    )

    hostname: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    asset_type: Mapped[AssetType] = mapped_column(
        Enum(
            AssetType,
            name="asset_type",
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        default=AssetType.OTHER,
        server_default=AssetType.OTHER.value,
    )

    ip_address: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
        index=True,
    )

    mac_address: Mapped[str | None] = mapped_column(
        String(17),
        nullable=True,
    )

    operating_system: Mapped[str | None] = mapped_column(
        String(200),
        nullable=True,
    )

    operating_system_version: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    environment: Mapped[AssetEnvironment] = mapped_column(
        Enum(
            AssetEnvironment,
            name="asset_environment",
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        default=AssetEnvironment.UNKNOWN,
        server_default=AssetEnvironment.UNKNOWN.value,
    )

    criticality: Mapped[AssetCriticality] = mapped_column(
        Enum(
            AssetCriticality,
            name="asset_criticality",
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        default=AssetCriticality.MEDIUM,
        server_default=AssetCriticality.MEDIUM.value,
    )

    status: Mapped[AssetStatus] = mapped_column(
        Enum(
            AssetStatus,
            name="asset_status",
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        default=AssetStatus.ACTIVE,
        server_default=AssetStatus.ACTIVE.value,
    )

    owner: Mapped[str | None] = mapped_column(
        String(200),
        nullable=True,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    tags: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )

    discovery_source: Mapped[AssetDiscoverySource] = mapped_column(
        Enum(
            AssetDiscoverySource,
            name="asset_discovery_source",
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        default=AssetDiscoverySource.MANUAL,
        server_default=AssetDiscoverySource.MANUAL.value,
    )

    external_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    organization = relationship(
        "Organization",
        back_populates="assets",
    )
