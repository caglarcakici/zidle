"""
Packet Engine - Raw TCP/IP packet build and capture.

Scapy wrapper: SYN, probe packets; IP ID read; spoofing.
"""

from __future__ import annotations

import random
from typing import Callable, Optional

from scapy.all import IP, TCP, sr1, send, conf

conf.verb = 0


class PacketEngine:
    """Packet send/receive and IP ID capture."""

    def __init__(self, timeout: float = 2.0, iface: Optional[str] = None):
        self.timeout = timeout
        self.iface = iface

    def build_syn(self, src_ip: str, dst_ip: str, dst_port: int) -> IP:
        """Build SYN packet (spoofed src) for target."""
        return (
            IP(src=src_ip, dst=dst_ip, id=random.randint(1, 65535))
            / TCP(sport=random.randint(1024, 65535), dport=dst_port, flags="S")
        )

    def build_probe(self, src_ip: str, dst_ip: str, dport: int = 80) -> IP:
        """Build probe packet (SYN) to zombie to elicit response and read IP ID."""
        return (
            IP(src=src_ip, dst=dst_ip, id=random.randint(1, 65535))
            / TCP(sport=random.randint(1024, 65535), dport=dport, flags="S")
        )

    def send_spoofed(self, pkt: IP) -> None:
        """Send spoofed packet (Layer 3)."""
        kwargs = {"verbose": False}
        if self.iface:
            kwargs["iface"] = self.iface
        send(pkt, **kwargs)

    def send_and_recv(self, pkt: IP) -> Optional[IP]:
        """Send packet and wait for one reply (for IP ID)."""
        reply = sr1(pkt, timeout=self.timeout, verbose=False)
        return reply

    def get_ip_id(self, pkt: IP) -> Optional[int]:
        """Read IP ID from packet."""
        if pkt is None or not pkt.haslayer(IP):
            return None
        return pkt[IP].id

    def probe_for_ip_ids(
        self,
        my_ip: str,
        zombie_ip: str,
        count: int = 10,
        probe_port: int = 80,
        stop_check: Optional[Callable[[], bool]] = None,
    ) -> list[int]:
        """
        Send probes to zombie and collect IP IDs from responses.

        Each probe is a SYN to probe_port; zombie replies (SYN/ACK or RST).
        If stop_check() returns True, the loop stops (for Ctrl+C).
        """
        ip_ids: list[int] = []
        for _ in range(count):
            if stop_check and stop_check():
                break
            pkt = self.build_probe(my_ip, zombie_ip, dport=probe_port)
            reply = self.send_and_recv(pkt)
            ip_id = self.get_ip_id(reply) if reply else None
            if ip_id is not None:
                ip_ids.append(ip_id)
        return ip_ids
