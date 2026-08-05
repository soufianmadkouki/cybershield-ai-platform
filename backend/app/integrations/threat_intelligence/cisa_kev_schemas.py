from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CisaKevVulnerability(BaseModel):
    model_config = ConfigDict(extra="allow")

    cve_id: str = Field(alias="cveID")
    vendor_project: str = Field(alias="vendorProject")
    product: str
    vulnerability_name: str = Field(alias="vulnerabilityName")
    date_added: date = Field(alias="dateAdded")
    short_description: str = Field(alias="shortDescription")
    required_action: str = Field(alias="requiredAction")
    due_date: date = Field(alias="dueDate")
    known_ransomware_campaign_use: str = Field(
        alias="knownRansomwareCampaignUse",
    )
    notes: str = ""
    cwes: list[str] = Field(default_factory=list)

    @field_validator(
        "cve_id",
        "vendor_project",
        "product",
        "vulnerability_name",
        "short_description",
        "required_action",
        "known_ransomware_campaign_use",
        "notes",
        mode="before",
    )
    @classmethod
    def strip_text(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip()

        return value

    @field_validator("cve_id")
    @classmethod
    def normalize_cve_id(cls, value: str) -> str:
        return value.upper()

    @field_validator("cwes", mode="before")
    @classmethod
    def normalize_cwes_input(cls, value: object) -> object:
        if value is None:
            return []

        return value


class CisaKevCatalog(BaseModel):
    model_config = ConfigDict(extra="allow")

    title: str
    catalog_version: str = Field(alias="catalogVersion")
    date_released: datetime = Field(alias="dateReleased")
    count: int = Field(ge=0)
    vulnerabilities: list[CisaKevVulnerability]

    @field_validator("title", "catalog_version", mode="before")
    @classmethod
    def strip_catalog_text(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip()

        return value

    def provider_metadata(self) -> dict[str, Any]:
        return {
            "catalog_title": self.title,
            "catalog_version": self.catalog_version,
            "catalog_date_released": self.date_released.isoformat(),
            "catalog_count": self.count,
        }
