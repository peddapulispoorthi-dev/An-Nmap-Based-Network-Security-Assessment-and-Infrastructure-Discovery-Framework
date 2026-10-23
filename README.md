# Nmap-Based Network Security Assessment Framework

A dependency-free Python CLI that runs a repeatable Nmap assessment, parses its
XML output, prioritizes common exposure findings, and writes JSON and standalone
HTML reports.

> Use only on networks you own or have written permission to test. The
> authorization flag is an explicit confirmation, not a substitute for
> authorization. `scanme.nmap.org` is Nmap's practice target; follow its current
> usage policy and keep scans light.

## MVP features

- Required `--i-have-permission` confirmation and timestamped target audit log.
- Host discovery with IP address, status, MAC address/vendor, and hostnames.
- Open TCP ports and service/version detection.
- OS fingerprinting only when running as root (Linux/macOS).
- Optional Nmap `vuln` NSE scripts (`--vuln`).
- Traceroute per discovered live host.
- Rule-based, prioritized findings for risky services, outdated service
  versions, and NSE vulnerability output, with remediation guidance.
- Raw Nmap XML for each scan phase and `report.json` / `report.html` in a
  timestamped folder.
- Standard-library-only Python script; no pip packages are required.

## Requirements

- Python 3.8 or newer.
- Nmap installed and available on `PATH`.

Install Nmap on Kali/Ubuntu with `sudo apt install nmap`, or install Nmap using
the official installer for Windows/macOS. No Python packages need installation.

## Usage

```bash
python3 nmap_framework.py 192.168.56.0/24 --i-have-permission
sudo python3 nmap_framework.py 192.168.56.101 --i-have-permission --vuln --full
```

On Windows, use `py -3 nmap_framework.py <authorized-target>
--i-have-permission`. Run elevated only when required for approved OS detection.

Options:

- `--i-have-permission`: required confirmation that this target is authorized.
- `--vuln`: run Nmap's vulnerability-detection NSE scripts. Review their
  behavior and obtain approval before use.
- `--full`: scan all TCP ports; without this option Nmap scans its top 1000.
- `--allow-large`: explicitly permit a CIDR broader than IPv4 `/16` or IPv6
  `/112`.
- `--out DIR`: output root directory (default `scans`).
- `--timeout SECONDS`: per-phase timeout (default 900).

The scan creates `scans/<timestamp>/` with discovery, port/service, optional OS,
optional NSE, and per-host traceroute XML files plus `report.json` and
`report.html`. The timestamped target audit is appended to `logs/audit.log`.
Open `report.html` in a browser.

## Architecture

```text
CLI arguments -> authorization + target validation -> timestamped audit
  -> Phase 1: Nmap host discovery -> live host list
  -> Phase 2: open TCP ports and service/version detection
  -> Phase 3: OS detection (root only; otherwise skipped)
  -> Phase 4: optional NSE vuln checks
  -> Phase 5: traceroute per discovered host
  -> XML parsing -> prioritized findings and risk scores -> JSON + HTML
```

Nmap is launched with `subprocess.run` using a list of arguments and
`shell=False`. The standard library's `xml.etree.ElementTree` parses Nmap XML;
HTML output escapes discovered values.

## Lab setup

Create an isolated VirtualBox or VMware host-only network. Attach Kali as the
scanner and Metasploitable 2 plus an Ubuntu/Windows VM as lab targets. Confirm
the lab addresses and written scope before scanning. Keep vulnerable VMs off
bridged and public networks.

## Demo plan for the Computer Networks course

1. Scan an authorized lab VM and inspect the JSON and HTML report.
2. Capture traffic in Wireshark and compare the SYN (`-sS`), connect (`-sT`),
   and UDP (`-sU`) scan patterns using Nmap directly on the isolated lab.
3. Show a prioritized finding, apply an approved defensive configuration change,
   rescan, and compare the before/after report observations.

See [docs/DEMO.md](docs/DEMO.md) for a step-by-step presentation script.

## Limitations

- IDS/firewalls and packet loss can distort discovery and service results.
- UDP scans are intentionally not part of this MVP.
- Root-dependent OS detection may be unavailable; traceroute can be incomplete.
- Version banners can be missing, inaccurate, or backported by vendors.
- Findings and risk scores are heuristics and indicators, not proof of
  exploitability, a complete vulnerability database, or a compliance assessment.
- Results are a point-in-time snapshot. Review and validate results with the
  system owner before taking remediation action.

## Future scope (not in MVP)

CVE/NVD lookups, scan diffing, web dashboard, scheduling, alerts, IPv6-focused
workflows, and UDP scanning.

## Testing

The test suite uses Python's built-in `unittest` and saved XML fixtures; it does
not require Nmap or network access:

```bash
python -m unittest discover -s tests -v
make test
```

## Vercel static report

The `public/` directory contains a static copy of the latest Nmap practice-target
report. The public copy intentionally omits traceroute hops to avoid publishing
local network paths. Import this Git repository into Vercel with the
**Other** framework preset and deploy the repository root; `vercel.json` sets
`public/` as the output directory. This static deployment displays a saved
report only; Vercel does not run the Python/Nmap scanner.
