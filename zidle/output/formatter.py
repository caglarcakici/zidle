"""CLI and JSON output formatters."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.table import Table

from zidle.models.scan_result import ScanResult
from zidle.models.zombie import ZombieProfile


def format_table(scan_result: ScanResult) -> None:
    """Print scan result as table."""
    console = Console()
    table = Table(title=f"Idle Scan: {scan_result.target} (zombie: {scan_result.zombie})")
    table.add_column("Port", style="cyan")
    table.add_column("State", style="green")
    for pr in scan_result.ports:
        state_style = {
            "open": "green",
            "closed": "dim",
            "filtered": "yellow",
            "unknown": "red",
        }.get(pr.state.value, "white")
        table.add_row(str(pr.port), f"[{state_style}]{pr.state.value}[/]")
    console.print(table)


def format_json(obj: Any) -> str:
    """Serialize Pydantic model or dict to JSON string."""
    if hasattr(obj, "model_dump"):
        return json.dumps(obj.model_dump(), indent=2, ensure_ascii=False)
    return json.dumps(obj, indent=2, ensure_ascii=False)


def format_zombie_profile(profile: ZombieProfile) -> None:
    """Print single zombie profile."""
    console = Console()
    status = "[green]✓ Suitable[/]" if profile.is_zombie else "[red]✗ Not suitable[/]"
    console.print(f"\n{profile.ip}: {status}")
    console.print(f"  Probe port: {profile.probe_port}")
    console.print(f"  Avg delta: {profile.avg_delta}, Stddev: {profile.stddev}")
    console.print(f"  Noise score: {profile.noise_score}, Samples: {profile.sample_count}\n")


def format_zombie_profiles(
    profiles: list[ZombieProfile],
    zombies_only: bool = False,
) -> None:
    """Print multiple zombie profiles as table (with probe port column)."""
    console = Console()
    total = len(profiles)
    display = [p for p in profiles if p.is_zombie] if zombies_only else profiles
    if not display:
        console.print(f"[yellow]No suitable zombies found ({total} IPs scanned).[/]")
        return
    zombie_count = sum(1 for p in profiles if p.is_zombie)
    title = f"Zombie Scan ({len(display)} shown"
    if zombies_only:
        title += f", {total} scanned"
    title += ")"
    table = Table(title=title)
    table.add_column("IP", style="cyan")
    table.add_column("Probe Port", justify="right")
    table.add_column("Status", style="green")
    table.add_column("Avg Delta", justify="right")
    table.add_column("Stddev", justify="right")
    table.add_column("Noise", justify="right")
    table.add_column("Samples", justify="right")
    for p in display:
        status = "[green]✓ Suitable[/]" if p.is_zombie else "[red]✗ No[/]"
        table.add_row(
            p.ip,
            str(p.probe_port),
            status,
            f"{p.avg_delta:.2f}",
            f"{p.stddev:.2f}",
            f"{p.noise_score:.2f}",
            str(p.sample_count),
        )
    console.print(table)
    if not zombies_only and zombie_count > 0:
        console.print(f"\n[green]→ {zombie_count} suitable zombie(s) found.[/]")
