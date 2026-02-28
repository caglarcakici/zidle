"""Scan result models."""

from enum import Enum

from pydantic import BaseModel, Field


class PortState(str, Enum):
    """Port state."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"


class PortResult(BaseModel):
    """Single port scan result."""

    port: int = Field(..., ge=1, le=65535)
    state: PortState = Field(...)


class ScanResult(BaseModel):
    """Full idle scan result."""

    zombie: str = Field(..., description="Zombie IP used")
    target: str = Field(..., description="Target IP scanned")
    ports: list[PortResult] = Field(default_factory=list)
