"""
Zidle - Zombie Idle Scan CLI.
"""

from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from zidle.models.zombie import ZombieProfile

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
    ex_table.add_row("Multiple probe ports", "[bold]zidle profile 192.168.1.0/24 --probe-port 80,443,22[/]")
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


def _zombies_found_renderable(zombies_found: list[ZombieProfile]) -> Panel:
    """Build a panel showing zombies found so far (for live display)."""
    if not zombies_found:
        return Panel(
            "[dim]No suitable zombies yet...[/]",
            title="[bold green]Zombies found[/]",
            border_style="green",
        )
    t = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
    t.add_column("IP", style="cyan")
    t.add_column("Probe Port", justify="right")
    t.add_column("Avg Delta", justify="right")
    t.add_column("Noise", justify="right")
    for p in zombies_found:
        t.add_row(p.ip, str(p.probe_port), f"{p.avg_delta:.2f}", f"{p.noise_score:.2f}")
    return Panel(t, title=f"[bold green]Zombies found[/] ({len(zombies_found)})", border_style="green")


EPILOG_PROFILE = "Target: CIDR, range, or list. Probe ports: 80 or 80,443,22. Examples: zidle profile 192.168.1.10 | zidle profile 192.168.1.0/24 --probe-port 80,443,22"


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
    probe_port: str = typer.Option(
        "80", "--probe-port",
        help="Port(s) for SYN probe: 80 or 80,443,22 [default: 80]",
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

    try:
        probe_ports = parse_ports(probe_port)
    except ValueError as e:
        typer.echo(f"Error: Invalid probe-port: {e}", err=True)
        raise typer.Exit(1)
    if not probe_ports:
        probe_ports = [80]

    profiler = ZombieProfiler()
    profiles: list = []
    zombies_found: list[ZombieProfile] = []
    total_tasks = len(targets) * len(probe_ports)
    console = Console(force_terminal=True)

    progress = Progress(
        TextColumn("[bold blue]Scanning[/]"),
        TextColumn("[cyan]{task.fields[info]}[/]", justify="left"),
        BarColumn(bar_width=24, complete_style="green", finished_style="bold green"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        expand=False,
    )
    task_id = progress.add_task("", total=total_tasks, info="")
    completed = 0

    with Live(
        Group(_zombies_found_renderable(zombies_found), progress),
        console=console,
        refresh_per_second=8,
    ) as live:
        for ip in targets:
            for port in probe_ports:
                progress.update(task_id, info=f"{ip}:{port}", completed=completed)
                p = profiler.profile(my_ip, ip, sample_count=samples, probe_port=port)
                profiles.append(p)
                if p.is_zombie:
                    zombies_found.append(p)
                completed += 1
                progress.update(task_id, completed=completed)
                live.update(Group(_zombies_found_renderable(zombies_found), progress))

    if json_output:
        if zombies_only:
            profiles = [p for p in profiles if p.is_zombie]
        typer.echo(format_json([p.model_dump() for p in profiles]))
    else:
        console.print()
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
