"""
Zombie Analyzer (IP ID Profiler).

Determines if a given IP is suitable as a zombie (predictable IP ID, low noise).
"""

from __future__ import annotations

import statistics
from typing import Callable, Optional

from zidle.core.packets import PacketEngine
from zidle.models.zombie import ZombieProfile


class ZombieProfiler:
    """Evaluates zombie suitability from IP ID profile."""

    def __init__(
        self,
        packet_engine: Optional[PacketEngine] = None,
        min_samples: int = 6,
        max_noise_score: float = 0.3,
        expected_delta_min: float = 0.8,
        expected_delta_max: float = 1.5,
    ):
        self.engine = packet_engine or PacketEngine()
        self.min_samples = min_samples
        self.max_noise_score = max_noise_score
        self.expected_delta_min = expected_delta_min
        self.expected_delta_max = expected_delta_max

    def _compute_deltas(self, ip_ids: list[int]) -> list[float]:
        """Compute consecutive IP ID differences."""
        if len(ip_ids) < 2:
            return []
        return [float(ip_ids[i + 1] - ip_ids[i]) for i in range(len(ip_ids) - 1)]

    def _compute_noise_score(self, deltas: list[float]) -> float:
        """Noise score 0–1; high stddev or inconsistent deltas → high score."""
        if not deltas:
            return 1.0
        mean_delta = statistics.mean(deltas)
        try:
            stddev = statistics.stdev(deltas)
        except statistics.StatisticsError:
            stddev = 0.0
        ideal = 1.0
        mean_dev = abs(mean_delta - ideal)
        noise = min(1.0, (mean_dev * 2 + stddev) / 2)
        return round(noise, 3)

    def profile(
        self,
        my_ip: str,
        zombie_ip: str,
        sample_count: int = 10,
        probe_port: int = 80,
        stop_check: Optional[Callable[[], bool]] = None,
    ) -> ZombieProfile:
        """
        Profile a zombie candidate.

        Returns:
            ZombieProfile with suitability and probe_port used.
        """
        ip_ids = self.engine.probe_for_ip_ids(
            my_ip,
            zombie_ip,
            count=sample_count,
            probe_port=probe_port,
            stop_check=stop_check,
        )

        if len(ip_ids) < self.min_samples:
            return ZombieProfile(
                ip=zombie_ip,
                is_zombie=False,
                probe_port=probe_port,
                avg_delta=0.0,
                stddev=0.0,
                noise_score=1.0,
                sample_count=len(ip_ids),
                ip_ids=ip_ids,
            )

        deltas = self._compute_deltas(ip_ids)
        avg_delta = statistics.mean(deltas)
        try:
            stddev = statistics.stdev(deltas)
        except statistics.StatisticsError:
            stddev = 0.0
        noise_score = self._compute_noise_score(deltas)

        is_zombie = (
            self.expected_delta_min <= avg_delta <= self.expected_delta_max
            and noise_score <= self.max_noise_score
        )

        return ZombieProfile(
            ip=zombie_ip,
            is_zombie=is_zombie,
            probe_port=probe_port,
            avg_delta=round(avg_delta, 3),
            stddev=round(stddev, 3),
            noise_score=noise_score,
            sample_count=len(ip_ids),
            ip_ids=ip_ids,
        )
