# Zidle – Zombie Idle Scan

Python tool for stealth port scanning using the zombie idle scan technique (Nmap `-sI` style). Modular and pipeline-friendly.

## Requirements

- Python 3.10+
- **Root or `CAP_NET_RAW`** (raw packet send)
- Linux (Scapy raw socket support; macOS has limitations)

## Install

### Option 1: Direct install

```bash
git clone https://github.com/caglarcakici/zidle.git
cd zidle
pip install -e .
```

This installs the **`zidle`** command.

### Option 2: Virtual environment (recommended on Kali / Debian)

On Kali or other Debian-based systems, system Python packages can conflict with pip. Using a **venv** keeps dependencies isolated and avoids touching system packages:

```bash
git clone https://github.com/caglarcakici/zidle.git
cd zidle
python3 -m venv .venv
source .venv/bin/activate    # Linux/macOS
pip install -e .
```

Run `zidle` with the venv activated:

```bash
zidle --help
zidle profile 192.168.1.0/24
zidle scan -z ZOMBIE_IP -t TARGET_IP -p 22,80,443
```

Because raw sockets need root, use one of:

```bash
sudo .venv/bin/zidle --help
sudo .venv/bin/python -m zidle profile 192.168.1.0/24
# or with venv activated:
sudo $(which zidle) profile 192.168.1.0/24
```

(On Windows: `.venv\Scripts\activate` and `python -m zidle`.)

### After install

```bash
zidle --help
zidle guide
zidle profile 192.168.1.0/24
zidle scan -z ZOMBIE_IP -t TARGET_IP -p 22,80,443
```

Without installing, from the project root: `python -m zidle`.

## Usage

### Zombie profiling

Profile one IP or Nmap-style ranges to find zombie candidates. The **probe port** used for each host is shown in the table and in JSON output.

```bash
# Single IP
sudo zidle profile 192.168.1.10

# CIDR
sudo zidle profile 192.168.1.0/24

# Range (last octet)
sudo zidle profile 192.168.1.1-254

# List (last octets or full IPs)
sudo zidle profile 192.168.1.1,2,5,6

# Custom probe port (default 80)
sudo zidle profile 192.168.1.0/24 --probe-port 443

# Show only suitable zombies
sudo zidle profile 192.168.1.0/24 --zombies-only
sudo zidle profile 192.168.1.1-50 -z --json
```

### Idle scan

Scan a target using a profiled zombie:

```bash
sudo zidle scan --zombie 192.168.1.10 --target 192.168.1.20 -p 22,80,443
sudo zidle scan -z 192.168.1.10 -t 192.168.1.20 -p 1-1000 --json
```

### Override our IP

If auto-detect fails:

```bash
sudo zidle scan -z 192.168.1.10 -t 192.168.1.20 -p 80 --my-ip 192.168.1.5
```

## Project layout

```
zidle/
├── cli.py
├── zidle/
│   ├── core/
│   │   ├── packets.py      # Scapy wrapper
│   │   ├── ipid_profile.py # Zombie profiler
│   │   └── idle_scan.py   # Idle scan engine
│   ├── models/
│   ├── output/
│   └── utils.py
└── requirements.txt
```

## How it works

1. **Zombie:** A host with predictable IP ID and low traffic.
2. **Probe:** Send SYN to the candidate (default port 80); read IP ID from replies.
3. **Spoofed SYN:** Send SYN to target with zombie’s IP as source.
4. **Open port:** Target sends SYN/ACK to zombie → zombie sends RST → IP ID increases.
5. **Closed port:** Target sends RST to zombie → zombie does not reply → IP ID stable.
6. Compare IP ID before/after to infer port state.

## License

MIT
