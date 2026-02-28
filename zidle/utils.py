"""Helper utilities."""

from __future__ import annotations

import ipaddress
import socket
from typing import Optional

from scapy.all import conf, get_if_addr


def _get_my_ip_via_socket(dst_ip: str) -> Optional[str]:
    """Return local IP used for route to dst (macOS/Linux compatible)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((dst_ip, 1))
            return s.getsockname()[0]
    except (OSError, socket.error):
        return None


def get_my_ip(dst_ip: Optional[str] = None) -> Optional[str]:
    """
    Return our interface IP for the route to dst_ip.
    Tries socket first (macOS/Linux), then Scapy route.
    """
    if dst_ip:
        ip = _get_my_ip_via_socket(dst_ip)
        if ip:
            return ip
        try:
            _dst, iface, _gw = conf.route.route(dst_ip)
            return get_if_addr(iface)
        except Exception:
            pass
        return None
    try:
        return get_if_addr(conf.iface)
    except Exception:
        pass
    if dst_ip is None:
        return _get_my_ip_via_socket("8.8.8.8")
    return None


def parse_targets(target_spec: str) -> list[str]:
    """
    Parse Nmap-style target spec into list of IPs.

    Supported: CIDR (192.168.1.0/24), range (192.168.1.1-254),
    list (192.168.1.1,2,5,6 or full IPs).
    """
    target_spec = target_spec.strip().replace(" ", "")
    if not target_spec:
        return []

    if "/" in target_spec:
        try:
            net = ipaddress.ip_network(target_spec, strict=False)
            return [str(ip) for ip in net.hosts()]
        except ValueError:
            raise ValueError(f"Invalid CIDR: {target_spec}")

    if "-" in target_spec and "/" not in target_spec:
        base, range_part = target_spec.rsplit("-", 1)
        try:
            lo = int(base.split(".")[-1])
            hi = int(range_part)
        except (ValueError, IndexError):
            raise ValueError(f"Invalid range: {target_spec}")
        if not (0 <= lo <= 255 and 0 <= hi <= 255):
            raise ValueError(f"Invalid octet range: {target_spec}")
        if lo > hi:
            lo, hi = hi, lo
        base_parts = base.rsplit(".", 1)[0]
        return [f"{base_parts}.{i}" for i in range(lo, hi + 1)]

    # Liste: 192.168.1.1,2,5,6 veya 192.168.1.1,192.168.1.5
    if "," in target_spec:
        parts = target_spec.split(",")
        first = parts[0]
        rest = parts[1:]

        # Son oktet listesi: 192.168.1.1,2,5,6
        if rest and all(
            p.isdigit() and 0 <= int(p) <= 255 for p in rest
        ):
            try:
                base = first.rsplit(".", 1)[0]
                octets = [int(first.split(".")[-1])] + [int(p) for p in rest]
                return [f"{base}.{o}" for o in sorted(set(octets))]
            except (ValueError, IndexError):
                pass

        # Tam IP listesi
        result: list[str] = []
        for p in parts:
            try:
                ipaddress.ip_address(p.strip())
                result.append(p.strip())
            except ValueError:
                raise ValueError(f"Invalid IP: {p}")
        return sorted(set(result), key=lambda x: ipaddress.ip_address(x))

    try:
        ipaddress.ip_address(target_spec)
        return [target_spec]
    except ValueError:
        raise ValueError(f"Invalid target: {target_spec}")


def parse_ports(port_spec: str) -> list[int]:
    """Parse port spec: 80,443 or 80-100 or 22,80-100,443. Returns sorted unique ports."""
    result: set[int] = set()
    for part in port_spec.replace(" ", "").split(","):
        if "-" in part:
            a, b = part.split("-", 1)
            lo, hi = int(a.strip()), int(b.strip())
            result.update(range(lo, hi + 1))
        else:
            result.add(int(part.strip()))
    return sorted(result)
