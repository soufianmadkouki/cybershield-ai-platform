from datetime import date

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EpssScoreRecord(BaseModel):
    model_config = ConfigDict(extra="allow")

    cve: str = Field(min_length=1, max_length=32)
    epss: float = Field(ge=0, le=1)
    percentile: float = Field(ge=0, le=1)
    date: date

    @field_validator("cve")
    @classmethod
    def normalize_cve(cls, value: str) -> str:
        return value.strip().upper()


class EpssApiResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    status: str
    status_code: int = Field(alias="status-code")
    version: str
    total: int = Field(ge=0)
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=100, ge=0)
    data: list[EpssScoreRecord]

    @field_validator("status", "version", mode="before")
    @classmethod
    def strip_text(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip()

        return value
