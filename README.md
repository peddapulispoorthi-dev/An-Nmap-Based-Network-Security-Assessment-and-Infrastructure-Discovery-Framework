# Nmap Network Security Assessment Framework

A permission-gated Python CLI and local web dashboard for repeatable Nmap-based
network discovery, service inventory, risk review, scan comparison, and reports.
It is intended for college labs and authorized assessments; it does not exploit
vulnerabilities or run denial-of-service tests.

## Features

- Host discovery, TCP port/service scanning, optional OS detection, Nmap `vuln`
  NSE checks, traceroute, and optional top-50 UDP scanning.
- `quick`, `standard`, and `full` profiles; elevated-privilege phases are skipped
  with a progress message when unavailable.
- Explicit authorization confirmation, IPv4/IPv6/hostname/CIDR validation,
  `/16` maximum IPv4 CIDR breadth by default, and timestamped audit logging.
- Nmap XML parsing without `python-nmap`; SQLite history and host/port/finding
  tables; risk findings and score; comparisons across saved scans.
- JSON, CSV, Markdown, and self-contained HTML reports.
- Loopback-first Flask dashboard with CSRF and same-origin validation,
  background progress, topology, history, comparisons, and downloads.

## Architecture

```text
CLI / Flask UI
      |
      +-- target validation + permission acknowledgement + audit log
      |
      +-- profile/phase orchestrator -- argument-list subprocess --> Nmap
      |                                                    |
      |                                                    +--> XML parser
      +-- analyzer --> SQLite history <--> scan diff
      |                     |
      +-- JSON / CSV / Markdown / HTML report generator
```

## Requirements and installation

Python 3.10 or newer and Nmap are required for real scans. Flask and pytest are
pinned in `requirements.txt`; the framework otherwise uses the standard library.

### Kali Linux / Ubuntu

```bash
sudo apt update
sudo apt install -y python3 python3-venv nmap
cd nmap-framework
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Run privileged phases with the appropriate approved system privileges, for
example `sudo .venv/bin/python -m nmapfw ...`. Do not run privileged scans on
systems or networks outside your authorization.

### Windows

1. Install Python 3.10+ and Nmap from their official distributions.
2. Ensure `nmap.exe` is on `PATH`.
3. From PowerShell:

```powershell
cd nmap-framework
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

The default Windows process uses TCP connect scans; raw-socket-dependent SYN and
OS-detection phases may be unavailable. Elevated access does not expand your
authorization to scan targets.

## CLI usage

Every scan requires the explicit `--i-have-permission` acknowledgement:

```bash
python -m nmapfw scan 192.168.56.101 --profile quick --i-have-permission
python -m nmapfw scan 192.168.56.101 --profile standard --i-have-permission
python -m nmapfw scan 192.168.56.101 --profile full --i-have-permission
python -m nmapfw scan 192.168.56.101 --profile quick --vuln --udp --i-have-permission
python -m nmapfw scan 192.168.56.0/24 --profile standard --i-have-permission --out ./assessment-output
```

Profiles:

| Profile | Phases |
|---|---|
| `quick` | Discovery and top 100 TCP ports |
| `standard` | Discovery, top 1000 TCP ports, service detection, OS detection when privileged |
| `full` | Discovery, all TCP ports, service detection, OS detection when privileged, NSE vulnerability checks, traceroute, and top-50 UDP |

The profile `--vuln` and `--udp` switches can add those phases to any profile.
CIDR ranges broader than IPv4 `/16` (or IPv6 `/112`) are rejected unless
`--allow-large` is explicitly supplied.

Saved scan commands:

```bash
python -m nmapfw history
python -m nmapfw show <scan_id>
python -m nmapfw diff <older_scan_id> <newer_scan_id>
python -m nmapfw report <scan_id> --format html
python -m nmapfw report <scan_id> --format json --out ./report.json
python -m nmapfw report <scan_id> --format csv --out ./report.csv
python -m nmapfw report <scan_id> --format md --out ./report.md
```

Scan XML files, reports, and SQLite history are stored under `scans/`; audit
records are stored in `logs/audit.log`. Both directories' generated data is
gitignored. The `--out DIR` option selects a scan/report output root.

## Web dashboard

```bash
python -m nmapfw.web.app
```

Open <http://127.0.0.1:5000>. The dashboard binds to loopback only by default.
The new-scan form requires the authorization checkbox and a same-origin CSRF
token. A single scan can run at a time. Do not expose the development server to
untrusted networks.

## Lab setup

1. Create a VirtualBox **host-only** network with no bridge to a public network.
2. Attach a Kali Linux VM and a Metasploitable 2 VM to that host-only network.
3. Record the lab-assigned addresses and verify connectivity from Kali.
4. Run this framework from the authorized lab host/VM and scan only the
   Metasploitable VM or the specific isolated lab range you control.
5. Keep the vulnerable VM disconnected from production and public networks.

Metasploitable 2 is intentionally vulnerable. Keep it isolated; this project
uses its scan results only for inventory and assessment and does not exploit it.

## Tests and development

```bash
python -m pytest -q
make test
make install
make scan-example
make web
```

The sample XML fixtures and mocked runner tests allow the test suite to pass
without Nmap or network access.

## Screenshots

Add screenshots of the home/authorization form, scan results, topology, history,
and report here when preparing a presentation.

## Legal and ethical notice

Only scan hosts and networks you own or have explicit written permission to
assess. Authorization is required even for discovery or service inventory.
Nmap's third-party NSE scripts may have target-specific effects; review their
behavior and obtain approval before using `--vuln`. Follow institutional
policies, applicable laws, and the scope supplied by the asset owner.

## Limitations

- Risk scoring uses transparent heuristic rules, not a complete vulnerability
  database or a compliance certification.
- Version banners can be missing, inaccurate, or backported by vendors.
- NSE output is retained and lightly interpreted; reported vulnerability checks
  need manual validation and remediation planning.
- OS detection and SYN scanning depend on Nmap, platform support, and privileges.
- Large scopes can take considerable time. No distributed scan scheduling,
  authentication testing, exploit verification, or active remediation is provided.
- Results are point-in-time snapshots and should not be treated as guarantees.

## Future scope

Potential extensions include authenticated asset inventory imports, configurable
organization-owned finding rules, signed report exports, RBAC for a hardened
deployment, and scheduled re-assessments with notification workflows.

## Design decisions

- Nmap is called with an argument list and `shell=False`; XML is parsed with
  `xml.etree.ElementTree`.
- Scanning is opt-in and permission-gated in both interfaces. No exploit or
  denial-of-service feature is included.
- Hostnames, IPs, and bounded CIDRs are validated before scanning; large ranges
  require an explicit override.
- SQLite stores scan metadata plus normalized host/port/finding rows and a
  serialized scan for reliable history reconstruction.
- The dashboard uses Flask's autoescaped templates, CSRF tokens, same-origin
  checks, a single active background scan, and loopback binding by default.
