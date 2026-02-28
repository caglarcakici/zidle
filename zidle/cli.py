"""
Zidle - Zombie Idle Scan CLI.
"""

from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from zidle import __version__
from zidle.core.idle_scan import IdleScanEngine
from zidle.core.ipid_profile import ZombieProfiler
from zidle.core.packets import PacketEngine
from zidle.output.formatter import (
    format_json,
    format_table,
    format_zombie_profile,
    format_zombie_profiles,
)
from zidle.utils import get_my_ip, parse_ports, parse_targets

app = typer.Typer(
    name="zidle",
    help="Zombie Idle Scan - Stealth port scanning using hosts with predictable IP ID.",
    add_completion=False,
    no_args_is_help=True,
    epilog="Run 'zidle guide' for full reference and examples. Requires root or CAP_NET_RAW.",
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"zidle {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(None, "--version", "-v", callback=_version_callback),
) -> None:
    """Zidle - Zombie Idle Scan. Use 'zidle guide' for full reference."""
    pass


def _print_guide() -> None:
    """Print Rich-formatted quick reference."""
    c = Console()
    c.print()
    c.print(Panel.fit(
        "[bold]zidle[/] — Zombie Idle Scan\n"
        "Stealth port scanning using hosts with predictable IP ID.\n\n"
        "[dim]Requires root or CAP_NET_RAW.[/]",
        title="About",
        border_style="blue",
    ))
    c.print()

    cmd_table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    cmd_table.add_column("Command", style="cyan")
    cmd_table.add_column("Description")
    cmd_table.add_column("Help")
    cmd_table.add_row(
        "profile [TARGET]",
        "Find zombie candidates (IP ID profile)",
        "[dim]zidle profile --help[/]",
    )
    cmd_table.add_row(
        "scan -z IP -t IP [-p PORTS]",
        "Run idle scan using a profiled zombie",
        "[dim]zidle scan --help[/]",
    )
    cmd_table.add_row(
        "guide",
        "Show this reference",
        "[dim]zidle guide[/]",
    )
    c.print(Panel(cmd_table, title="Commands", border_style="green"))
    c.print()

    ex_table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    ex_table.add_column("Action", style="yellow")
    ex_table.add_column("Example")
    ex_table.add_row("Profile one IP", "[bold]zidle profile 192.168.1.10[/]")
    ex_table.add_row("Profile range (CIDR)", "[bold]zidle profile 192.168.1.0/24[/]")
    ex_table.add_row("Profile range (Nmap)", "[bold]zidle profile 192.168.1.1-254[/]")
    ex_table.add_row("Profile list", "[bold]zidle profile 192.168.1.1,2,5,207[/]")
    ex_table.add_row("Zombies only + JSON", "[bold]zidle profile 192.168.1.0/24 -z -j[/]")
    ex_table.add_row("Idle scan", "[bold]zidle scan -z 192.168.1.207 -t 192.168.1.1 -p 22,80,443[/]")
    ex_table.add_row("Scan with probe port", "[bold]zidle scan -z Z -t T -p 1-1000 --probe-port 80[/]")
    c.print(Panel(ex_table, title="Examples", border_style="yellow"))
    c.print()

    opts = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    opts.add_column("Option", style="cyan")
    opts.add_column("Description")
    opts.add_row("-v, --version", "Show version")
    opts.add_row("--help", "Show help for command")
    c.print(Panel(opts, title="Global options", border_style="dim"))
    c.print()


@app.command()
def guide() -> None:
    """Show quick reference and examples (readable layout)."""
    _print_guide()


EPILOG_PROFILE = "Target: CIDR (192.168.1.0/24), range (1-254), or list (1,2,5). Examples: zidle profile 192.168.1.10 | zidle profile 192.168.1.0/24 -z -j"


@app.command(epilog=EPILOG_PROFILE)
def profile(
    target: str = typer.Argument(
        ...,
        help="Target IP or Nmap-style range (CIDR, 1-254, or 1,2,5)",
    ),
    my_ip: Optional[str] = typer.Option(
        None, "--my-ip", "-m",
        help="Our IP (if auto-detect fails)",
    ),
    probe_port: int = typer.Option(
        80, "--probe-port",
        help="Port for SYN probe [default: 80]",
    ),
    samples: int = typer.Option(
        10, "--samples", "-n",
        help="Probes per host [default: 10]",
    ),
    zombies_only: bool = typer.Option(
        False, "--zombies-only", "-z",
        help="Show only suitable zombies",
    ),
    json_output: bool = typer.Option(
        False, "--json", "-j",
        help="Output as JSON",
    ),
) -> None:
    """Profile zombie candidates: measure IP ID predictability and noise."""
    try:
        targets = parse_targets(target)
    except ValueError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)

    my_ip = my_ip or (get_my_ip(targets[0]) if targets else None)
    if not my_ip:
        typer.echo("Error: Could not detect our IP. Use --my-ip.", err=True)
        raise typer.Exit(1)

    targets = [t for t in targets if t != my_ip]

    if not targets:
        typer.echo("Error: No valid targets (only our own IP?).", err=True)
        raise typer.Exit(1)

    profiler = ZombieProfiler()
    profiles: list = []

    with typer.progressbar(targets, label="Scanning") as progress:
        for ip in progress:
            p = profiler.profile(my_ip, ip, sample_count=samples, probe_port=probe_port)
            profiles.append(p)

    if json_output:
        if zombies_only:
            profiles = [p for p in profiles if p.is_zombie]
        typer.echo(format_json([p.model_dump() for p in profiles]))
    else:
        format_zombie_profiles(profiles, zombies_only=zombies_only)


EPILOG_SCAN = "Ports: 22,80,443 or 1-1000 or 22,80-100,443. Example: zidle scan -z ZOMBIE_IP -t TARGET_IP -p 22,80,443"


@app.command(epilog=EPILOG_SCAN)
def scan(
    zombie: str = typer.Option(
        ..., "--zombie", "-z",
        help="Zombie IP (must be profiled and suitable)",
    ),
    target: str = typer.Option(
        ..., "--target", "-t",
        help="Target IP to scan",
    ),
    ports: str = typer.Option(
        "22,80,443", "--ports", "-p",
        help="Ports: 80,443 or 1-1000 or 22,80-100,443 [default: 22,80,443]",
    ),
    my_ip: Optional[str] = typer.Option(
        None, "--my-ip", "-m",
        help="Our IP (if auto-detect fails)",
    ),
    probe_port: int = typer.Option(
        80, "--probe-port",
        help="Port to probe zombie (must match profile) [default: 80]",
    ),
    timeout: float = typer.Option(
        2.0, "--timeout",
        help="Packet timeout in seconds [default: 2.0]",
    ),
    json_output: bool = typer.Option(
        False, "--json", "-j",
        help="Output as JSON",
    ),
) -> None:
    """Run idle scan: use zombie to probe target ports without revealing our IP."""
    my_ip = my_ip or get_my_ip(zombie) or get_my_ip(target)
    if not my_ip:
        typer.echo("Error: Could not detect our IP. Use --my-ip.", err=True)
        raise typer.Exit(1)

    try:
        port_list = parse_ports(ports)
    except ValueError as e:
        typer.echo(f"Error: Invalid port spec: {e}", err=True)
        raise typer.Exit(1)

    engine = PacketEngine(timeout=timeout)
    scanner = IdleScanEngine(packet_engine=engine)
    result = scanner.scan(my_ip, zombie, target, port_list, probe_port=probe_port)

    if json_output:
        typer.echo(format_json(result))
    else:
        format_table(result)
