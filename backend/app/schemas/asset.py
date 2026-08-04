from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    field_validator,
)

from app.models.asset_enums import (
    AssetCriticality,
    AssetDiscoverySource,
    AssetEnvironment,
    AssetStatus,
    AssetType,
)

MAC_ADDRESS_PATTERN = r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"


class AssetBase(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    hostname: str | None = Field(default=None, max_length=255)

    asset_type: AssetType = AssetType.OTHER
    ip_address: IPvAnyAddress | None = None

    mac_address: str | None = Field(
        default=None,
        max_length=17,
        pattern=MAC_ADDRESS_PATTERN,
    )

    operating_system: str | None = Field(
        default=None,
        max_length=200,
    )

    operating_system_version: str | None = Field(
        default=None,
        max_length=100,
    )

    environment: AssetEnvironment = AssetEnvironment.UNKNOWN
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    status: AssetStatus = AssetStatus.ACTIVE

    owner: str | None = Field(default=None, max_length=200)
    description: str | None = Field(default=None, max_length=5000)

    tags: dict[str, Any] = Field(default_factory=dict)

    discovery_source: AssetDiscoverySource = AssetDiscoverySource.MANUAL

    external_id: str | None = Field(default=None, max_length=255)
    last_seen_at: datetime | None = None

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        return value.strip()

    @field_validator("hostname")
    @classmethod
    def normalize_hostname(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        normalized = value.strip().lower()
        return normalized or None

    @field_validator("mac_address")
    @classmethod
    def normalize_mac_address(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        return value.upper()


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    hostname: str | None = Field(default=None, max_length=255)

    asset_type: AssetType | None = None
    ip_address: IPvAnyAddress | None = None

    mac_address: str | None = Field(
        default=None,
        max_length=17,
        pattern=MAC_ADDRESS_PATTERN,
    )

    operating_system: str | None = Field(default=None, max_length=200)
    operating_system_version: str | None = Field(
        default=None,
        max_length=100,
    )

    environment: AssetEnvironment | None = None
    criticality: AssetCriticality | None = None
    status: AssetStatus | None = None

    owner: str | None = Field(default=None, max_length=200)
    description: str | None = Field(default=None, max_length=5000)

    tags: dict[str, Any] | None = None
    discovery_source: AssetDiscoverySource | None = None

    external_id: str | None = Field(default=None, max_length=255)
    last_seen_at: datetime | None = None

    @field_validator("name")
    @classmethod
    def normalize_name(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        return value.strip()

    @field_validator("hostname")
    @classmethod
    def normalize_hostname(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        normalized = value.strip().lower()
        return normalized or None

    @field_validator("mac_address")
    @classmethod
    def normalize_mac_address(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        return value.upper()


class AssetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID

    name: str
    hostname: str | None
    asset_type: AssetType

    ip_address: str | None
    mac_address: str | None

    operating_system: str | None
    operating_system_version: str | None

    environment: AssetEnvironment
    criticality: AssetCriticality
    status: AssetStatus

    owner: str | None
    description: str | None
    tags: dict[str, Any]

    discovery_source: AssetDiscoverySource
    external_id: str | None
    last_seen_at: datetime | None

    created_at: datetime
    updated_at: datetime


class AssetListResponse(BaseModel):
    items: list[AssetResponse]
    total: int
    page: int
    size: int
    pages: int
