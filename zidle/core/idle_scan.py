"""
Idle Scan Engine.

Zombie kullanarak hedefe spoofed SYN gönderir,
IP ID değişimine göre port durumunu (open/closed/filtered) çıkarır.
"""

from __future__ import annotations

import time
from typing import Optional

from zidle.core.packets import PacketEngine
from zidle.models.scan_result import PortState, PortResult, ScanResult


class IdleScanEngine:
    """Runs zombie idle scan logic."""

    def __init__(
        self,
        packet_engine: Optional[PacketEngine] = None,
        probe_delay: float = 0.5,
        open_threshold: int = 2,
    ):
        self.engine = packet_engine or PacketEngine()
        self.probe_delay = probe_delay
        self.open_threshold = open_threshold

    def _get_zombie_ip_id(
        self,
        my_ip: str,
        zombie_ip: str,
        probe_port: int = 80,
    ) -> Optional[int]:
        """Probe zombie and return IP ID from response."""
        pkt = self.engine.build_probe(my_ip, zombie_ip, dport=probe_port)
        reply = self.engine.send_and_recv(pkt)
        return self.engine.get_ip_id(reply) if reply else None

    def scan_port(
        self,
        my_ip: str,
        zombie_ip: str,
        target_ip: str,
        port: int,
        probe_port: int = 80,
    ) -> PortState:
        """
        Idle scan for one port.
        OPEN: delta >= 2; CLOSED: delta <= 1; else FILTERED.
        """
        id_before = self._get_zombie_ip_id(my_ip, zombie_ip, probe_port)
        if id_before is None:
            return PortState.UNKNOWN

        syn_pkt = self.engine.build_syn(zombie_ip, target_ip, port)
        self.engine.send_spoofed(syn_pkt)

        time.sleep(self.probe_delay)

        id_after = self._get_zombie_ip_id(my_ip, zombie_ip, probe_port)
        if id_after is None:
            return PortState.UNKNOWN

        delta = (id_after - id_before) % 65536
        if delta > 32768:
            delta = delta - 65536

        if delta >= self.open_threshold:
            return PortState.OPEN
        if delta <= 1:
            return PortState.CLOSED
        return PortState.FILTERED

    def scan(
        self,
        my_ip: str,
        zombie_ip: str,
        target_ip: str,
        ports: list[int],
        probe_port: int = 80,
    ) -> ScanResult:
        """Run idle scan for multiple ports."""
        results: list[PortResult] = []
        for port in ports:
            state = self.scan_port(
                my_ip, zombie_ip, target_ip, port, probe_port=probe_port
            )
            results.append(PortResult(port=port, state=state))
        return ScanResult(zombie=zombie_ip, target=target_ip, ports=results)
