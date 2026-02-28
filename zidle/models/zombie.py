"""Zombie profile model."""

from pydantic import BaseModel, Field


class ZombieProfile(BaseModel):
    """Zombie suitability profile for an IP."""

    ip: str = Field(..., description="Candidate IP address")
    is_zombie: bool = Field(..., description="Suitable as zombie")
    probe_port: int = Field(default=80, ge=1, le=65535, description="Port used for probing (SYN)")
    avg_delta: float = Field(..., description="Mean of IP ID deltas")
    stddev: float = Field(default=0.0, description="Standard deviation (noise)")
    noise_score: float = Field(
        default=0.0,
        ge=0,
        le=1,
        description="0=quiet, 1=noisy",
    )
    sample_count: int = Field(default=0, description="Number of probes used")
    ip_ids: list[int] = Field(default_factory=list, description="Observed IP ID values")
