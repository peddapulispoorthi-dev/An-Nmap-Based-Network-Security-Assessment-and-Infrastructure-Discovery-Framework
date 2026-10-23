#!/usr/bin/env python3
"""Permission-gated Nmap assessment CLI using only the Python standard library."""

import argparse
import html
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


RISKY_PORTS = {
    21: ("High", "FTP may send credentials or data without encryption.",
         "Disable FTP or replace it with SFTP/FTPS; restrict access."),
    23: ("High", "Telnet sends credentials and session data in clear text.",
         "Disable Telnet and use SSH with key-based authentication."),
    69: ("Medium", "TFTP has no authentication and may expose or overwrite files.",
         "Disable TFTP or restrict it to an isolated, trusted network."),
    111: ("Medium", "RPC services can expose system procedures and expand attack surface.",
          "Disable unused RPC services and restrict access to trusted peers."),
    135: ("Medium", "Microsoft RPC endpoint mapping is exposed.",
          "Restrict RPC to trusted networks and apply system updates."),
    139: ("High", "NetBIOS session service may expose file and host information.",
          "Disable NetBIOS where unnecessary and restrict access at the firewall."),
    161: ("High", "SNMP may disclose sensitive device configuration.",
          "Use SNMPv3 and restrict management access to trusted sources."),
    445: ("High", "SMB exposure increases file disclosure and ransomware risk.",
          "Restrict SMB to trusted networks, disable SMBv1, and patch systems."),
    512: ("High", "rexec is an insecure remote execution service.",
          "Disable rexec and use SSH for remote administration."),
    513: ("High", "rlogin may allow weakly authenticated remote access.",
          "Disable rlogin and use SSH with strong authentication."),
    514: ("High", "rsh provides insecure remote shell access.",
          "Disable rsh and use SSH with strong authentication."),
    1433: ("Medium", "MSSQL database access is exposed on the network.",
           "Restrict database access to approved application hosts."),
    1521: ("Medium", "Oracle database listener is exposed on the network.",
           "Restrict listener access to trusted application hosts."),
    2049: ("High", "NFS may expose mounted files or sensitive data.",
           "Restrict NFS exports and firewall access to trusted systems."),
    3306: ("Medium", "MySQL database access is exposed on the network.",
           "Bind MySQL to required interfaces and restrict client access."),
    3389: ("High", "RDP is exposed to network login attempts.",
           "Restrict RDP through VPN or allowlists, enforce MFA, and patch."),
    5432: ("Medium", "PostgreSQL database access is exposed on the network.",
           "Restrict PostgreSQL to approved application hosts."),
    5900: ("High", "VNC remote desktop access is exposed.",
           "Disable VNC when unused or tunnel it through an authenticated VPN."),
    6379: ("High", "Redis may expose data if authentication or network controls are weak.",
           "Require authentication, bind to trusted interfaces, and firewall access."),
    9200: ("High", "Elasticsearch API may expose index data or administrative operations.",
           "Require authentication and TLS; restrict access to trusted hosts."),
    27017: ("High", "MongoDB may expose databases if network controls are weak.",
            "Enable authentication and TLS, and restrict access to trusted clients."),
}

VERSION_RULES = (
    ("openssh", (7, 4), "Medium",
     "OpenSSH versions before 7.4 are outdated and may lack important security fixes."),
    ("apache httpd", (2, 4, 50), "High",
     "Apache HTTP Server versions before 2.4.50 are outdated; verify vendor advisories."),
    ("vsftpd", (3, 0, 3), "Medium",
     "vsftpd versions before 3.0.3 are outdated and should be upgraded."),
)
SEVERITY_POINTS = {"Critical": 35, "High": 25, "Medium": 15, "Low": 8}
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class AssessmentError(Exception):
    """A readable error that should be shown to the CLI user."""


def _utc_timestamp() -> str:
    """Return a timezone-aware UTC timestamp in ISO 8601 form."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def validate_target(target: str, allow_large: bool = False) -> str:
    """Validate an IPv4/IPv6 address, bounded CIDR, or DNS hostname."""
    value = target.strip()
    if not value or any(character in value for character in "\r\n\t ,;"):
        raise AssessmentError("Provide one non-empty IP address, hostname, or CIDR target.")
    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)
            minimum = 16 if network.version == 4 else 112
            if not allow_large and network.prefixlen < minimum:
                raise AssessmentError(
                    "Target range is too broad; use /{} or narrower, or add --allow-large.".format(minimum)
                )
            return str(network)
        return str(ipaddress.ip_address(value))
    except ValueError:
        if "/" in value or ":" in value:
            raise AssessmentError("Invalid IP address or CIDR target: {!r}".format(value))
    hostname = value.rstrip(".")
    if len(hostname) > 253 or not hostname:
        raise AssessmentError("Hostname must be between 1 and 253 characters.")
    if not all(HOST_LABEL.match(label) for label in hostname.split(".")):
        raise AssessmentError("Invalid hostname target: {!r}".format(value))
    return hostname.lower()


def has_root_privileges() -> bool:
    """Return whether the current POSIX process has root privileges."""
    return os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0


def _parse_nmap_xml(path: Path) -> List[Dict[str, Any]]:
    """Parse hosts, open ports, OS matches, NSE scripts, and traceroute hops."""
    try:
        root = ET.parse(str(path)).getroot()
    except (ET.ParseError, OSError) as error:
        raise AssessmentError("Could not parse Nmap XML {}: {}".format(path.name, error))
    hosts = []
    for node in root.findall("host"):
        status_node = node.find("status")
        addresses = node.findall("address")
        address_node = next(
            (item for item in addresses if item.get("addrtype") in ("ipv4", "ipv6")),
            None,
        )
        if address_node is None:
            continue
        mac_node = next((item for item in addresses if item.get("addrtype") == "mac"), None)
        ports = []
        for port_node in node.findall("./ports/port"):
            state_node = port_node.find("state")
            state = state_node.get("state", "unknown") if state_node is not None else "unknown"
            if state != "open":
                continue
            service_node = port_node.find("service")
            scripts = {
                item.get("id", "unknown"): item.get("output", "")
                for item in port_node.findall("script")
            }
            ports.append({
                "number": int(port_node.get("portid", "0")),
                "protocol": port_node.get("protocol", ""),
                "state": state,
                "service": service_node.get("name", "") if service_node is not None else "",
                "product": service_node.get("product", "") if service_node is not None else "",
                "version": service_node.get("version", "") if service_node is not None else "",
                "extra_info": service_node.get("extrainfo", "") if service_node is not None else "",
                "scripts": scripts,
            })
        matches = []
        for match in node.findall("./os/osmatch"):
            os_class = match.find("osclass")
            matches.append({
                "name": match.get("name", ""),
                "accuracy": int(match.get("accuracy", "0")),
                "family": os_class.get("osfamily", "") if os_class is not None else "",
            })
        traceroute = [{
            "ttl": int(hop.get("ttl", "0")),
            "ip": hop.get("ipaddr", ""),
            "hostname": hop.get("host", ""),
            "rtt": hop.get("rtt", ""),
        } for hop in node.findall("./trace/hop")]
        hosts.append({
            "address": address_node.get("addr", ""),
            "status": status_node.get("state", "unknown") if status_node is not None else "unknown",
            "mac": mac_node.get("addr", "") if mac_node is not None else "",
            "vendor": mac_node.get("vendor", "") if mac_node is not None else "",
            "hostnames": [
                item.get("name", "") for item in node.findall("./hostnames/hostname")
                if item.get("name")
            ],
            "ports": ports,
            "os_matches": matches,
            "traceroute": traceroute,
            "findings": [],
            "risk_score": 0,
        })
    return hosts


def _merge_hosts(host_map: Dict[str, Dict[str, Any]], incoming: List[Dict[str, Any]]) -> None:
    """Merge results from each Nmap phase by host address."""
    for host in incoming:
        address = host["address"]
        existing = host_map.get(address)
        if existing is None:
            host_map[address] = host
            continue
        if host["status"] != "unknown":
            existing["status"] = host["status"]
        for key in ("mac", "vendor"):
            if host[key]:
                existing[key] = host[key]
        existing["hostnames"] = sorted(set(existing["hostnames"] + host["hostnames"]))
        ports = {(item["protocol"], item["number"]): item for item in existing["ports"]}
        ports.update({(item["protocol"], item["number"]): item for item in host["ports"]})
        existing["ports"] = list(ports.values())
        if host["os_matches"]:
            existing["os_matches"] = host["os_matches"]
        if host["traceroute"]:
            existing["traceroute"] = host["traceroute"]


def analyze_hosts(hosts: List[Dict[str, Any]]) -> Tuple[int, str]:
    """Attach prioritized service/version/NSE findings and risk scores."""
    for host in hosts:
        findings = []
        for port in host["ports"]:
            rule = RISKY_PORTS.get(port["number"])
            if rule:
                severity, description, remediation = rule
                findings.append({
                    "title": "Exposed {} port {}".format(port["service"] or "service", port["number"]),
                    "severity": severity,
                    "description": description,
                    "remediation": remediation,
                    "port": port["number"],
                })
            version_match = re.search(r"(?<!\d)(\d+(?:\.\d+){1,3})", port["version"])
            service = "{} {}".format(port["product"], port["service"]).lower()
            if version_match:
                version = tuple(int(part) for part in version_match.group(1).split("."))
                for product, threshold, severity, description in VERSION_RULES:
                    width = max(len(version), len(threshold))
                    padded_version = version + (0,) * (width - len(version))
                    padded_threshold = threshold + (0,) * (width - len(threshold))
                    if product in service and padded_version < padded_threshold:
                        findings.append({
                            "title": "Outdated {} version {}".format(
                                port["product"] or port["service"], port["version"]
                            ),
                            "severity": severity,
                            "description": description,
                            "remediation": "Upgrade to a supported release and verify vendor security advisories.",
                            "port": port["number"],
                        })
            for script_id, output in port["scripts"].items():
                if "vulnerable" not in output.lower() or "not vulnerable" in output.lower():
                    continue
                findings.append({
                    "title": "NSE reported a vulnerability ({})".format(script_id),
                    "severity": "High",
                    "description": output,
                    "remediation": "Review the advisory, patch or mitigate the service, and rescan.",
                    "port": port["number"],
                    "cves": sorted(set(match.upper() for match in re.findall(
                        r"\bCVE-\d{4}-\d{4,7}\b", output, re.IGNORECASE
                    ))),
                })
        findings.sort(key=lambda item: (
            SEVERITY_ORDER.get(item["severity"], 99), item["title"], item.get("port", 0)
        ))
        host["findings"] = findings
        host["risk_score"] = min(
            100, sum(SEVERITY_POINTS.get(item["severity"], 0) for item in findings)
        )
    score = round(sum(host["risk_score"] for host in hosts) / len(hosts)) if hosts else 0
    label = "Low" if score < 20 else "Medium" if score < 40 else "High" if score < 70 else "Critical"
    return score, label


def _run_phase(
    targets: Sequence[str], arguments: Sequence[str], xml_path: Path, timeout: int
) -> List[Dict[str, Any]]:
    """Run one Nmap phase safely and return parsed hosts from its XML output."""
    executable = shutil.which("nmap")
    if not executable:
        raise AssessmentError("Nmap was not found. Install Nmap and ensure it is available on PATH.")
    xml_path.parent.mkdir(parents=True, exist_ok=True)
    command = [executable] + list(arguments) + ["-oX", str(xml_path)] + list(targets)
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False, shell=False
        )
    except subprocess.TimeoutExpired:
        raise AssessmentError("Nmap phase timed out after {} seconds.".format(timeout))
    except OSError as error:
        raise AssessmentError("Unable to start Nmap: {}".format(error))
    if completed.returncode:
        detail = completed.stderr.strip() or "Nmap exited with status {}.".format(completed.returncode)
        raise AssessmentError(detail)
    if not xml_path.is_file():
        raise AssessmentError("Nmap completed without producing XML output.")
    try:
        return _parse_nmap_xml(xml_path)
    except (TypeError, ValueError, KeyError) as error:
        raise AssessmentError(
            "Nmap XML {} contains invalid data: {}".format(xml_path.name, error)
        )


def _safe_filename(value: str) -> str:
    """Return a stable filename component for an address or hostname."""
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._") or "host"


def run_assessment(
    target: str,
    output_root: Path,
    permission: bool,
    include_vuln: bool = False,
    full: bool = False,
    allow_large: bool = False,
    timeout: int = 900,
    audit_log: Optional[Path] = None,
) -> Dict[str, Any]:
    """Run discovery, service scan, optional OS/NSE, and per-host traceroute."""
    if not permission:
        raise AssessmentError(
            "Scan refused: pass --i-have-permission only when authorized to assess this target."
        )
    validated = validate_target(target, allow_large=allow_large)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    output_dir = output_root / timestamp
    output_dir.mkdir(parents=True, exist_ok=False)
    audit_path = audit_log or Path("logs") / "audit.log"
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with audit_path.open("a", encoding="utf-8") as audit:
        audit.write("{} target={}\n".format(_utc_timestamp(), validated))

    scan = {
        "scan_id": timestamp,
        "started_at": _utc_timestamp(),
        "finished_at": "",
        "target": validated,
        "profile": "full" if full else "standard",
        "status": "completed",
        "errors": [],
        "hosts": [],
        "risk_score": 0,
        "risk_label": "Low",
        "output_dir": str(output_dir),
    }
    hosts: Dict[str, Dict[str, Any]] = {}
    phases = [("discovery", ["-sn"], [validated])]
    is_root = has_root_privileges()
    port_arguments = ["-sS" if is_root else "-sT", "-sV"]
    port_arguments.extend(["-p-",] if full else ["--top-ports", "1000"])
    phases.append(("ports-services", port_arguments, []))
    if is_root:
        phases.append(("os-detection", ["-O"], []))
    else:
        print("[os-detection] skipped (root/administrator privileges required)")
    if include_vuln:
        phases.append(("nse-vuln", ["--script", "vuln"], []))

    for phase, arguments, explicit_targets in phases:
        current_targets = explicit_targets or sorted(hosts)
        if not current_targets and not explicit_targets:
            print("[{}] skipped (no live hosts discovered)".format(phase))
            continue
        print("[{}] scanning {} target(s)".format(phase, len(current_targets)), flush=True)
        xml_file = output_dir / "{}.xml".format(phase)
        try:
            phase_hosts = _run_phase(current_targets, arguments, xml_file, timeout)
            if phase == "discovery":
                phase_hosts = [host for host in phase_hosts if host["status"] == "up"]
            _merge_hosts(hosts, phase_hosts)
        except AssessmentError as error:
            scan["errors"].append("{}: {}".format(phase, error))
            print("[{}] failed: {}".format(phase, error), file=sys.stderr)

    for address in sorted(hosts):
        print("[traceroute] {}".format(address), flush=True)
        try:
            traceroute_hosts = _run_phase(
                [address],
                ["--traceroute", "-sn"],
                output_dir / "traceroute-{}.xml".format(_safe_filename(address)),
                timeout,
            )
            _merge_hosts(hosts, traceroute_hosts)
        except AssessmentError as error:
            scan["errors"].append("traceroute {}: {}".format(address, error))
            print("[traceroute] {} failed: {}".format(address, error), file=sys.stderr)

    scan["hosts"] = [hosts[address] for address in sorted(hosts)]
    if scan["errors"]:
        scan["status"] = "partial" if scan["hosts"] else "failed"
    scan["risk_score"], scan["risk_label"] = analyze_hosts(scan["hosts"])
    scan["finished_at"] = _utc_timestamp()
    write_reports(scan, output_dir)
    return scan


def _risk_css(severity: str) -> str:
    return severity.lower() if severity.lower() in ("critical", "high", "medium", "low") else "info"


def render_html(scan: Dict[str, Any]) -> str:
    """Build a self-contained, escaped HTML report."""
    esc = lambda value: html.escape(str(value), quote=True)
    sections = []
    for host in scan["hosts"]:
        port_rows = "".join(
            "<tr><td>{}/{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                port["number"], esc(port["protocol"]), esc(port["state"]),
                esc(port["service"]), esc(port["product"]), esc(port["version"]),
                esc(port["extra_info"])
            )
            for port in host["ports"]
        ) or '<tr><td colspan="6">No open ports found</td></tr>'
        findings = "".join(
            '<li class="{}"><strong>{}: {}</strong><p>{}</p><p><b>Remediation:</b> {}</p></li>'.format(
                _risk_css(item["severity"]), esc(item["severity"]), esc(item["title"]),
                esc(item["description"]), esc(item["remediation"])
            )
            for item in host["findings"]
        ) or "<li>No prioritized findings.</li>"
        os_text = ", ".join(
            "{} ({}%)".format(esc(item["name"]), item["accuracy"])
            for item in host["os_matches"]
        ) or "Not detected"
        hops = " &rarr; ".join(
            esc(hop["hostname"] or hop["ip"] or "unknown") for hop in host["traceroute"]
        ) or "Not available"
        sections.append(
            "<section><h2>{} <small>Risk: {}/100</small></h2>"
            "<p>Status: {} | Hostname(s): {}</p><p>MAC: {} | Vendor: {}</p>"
            "<p>OS matches: {}</p><h3>Open ports and services</h3>"
            "<table><thead><tr><th>Port</th><th>State</th><th>Service</th>"
            "<th>Product</th><th>Version</th><th>Extra info</th></tr></thead>"
            "<tbody>{}</tbody></table><h3>Prioritized findings</h3><ul>{}</ul>"
            "<p>Traceroute: {}</p></section>".format(
                esc(host["address"]), host["risk_score"], esc(host["status"]),
                esc(", ".join(host["hostnames"]) or "None"), esc(host["mac"] or "Unknown"),
                esc(host["vendor"] or "Unknown"), os_text, port_rows, findings, hops
            )
        )
    errors = "".join("<li>{}</li>".format(esc(item)) for item in scan["errors"])
    return """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width"><title>Network Assessment Report</title>
<style>
body{{font:16px/1.5 system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#18212f;background:#f3f6fa}}
header,section{{background:white;padding:1.3rem;margin:1rem 0;border-radius:12px;box-shadow:0 2px 12px #172b4d15}}
.cards{{display:flex;gap:1rem;flex-wrap:wrap}}.card{{background:#edf2f8;padding:1rem;border-radius:8px}}
table{{width:100%;border-collapse:collapse}}td,th{{padding:.55rem;text-align:left;border-bottom:1px solid #dce3ec}}
.critical,.high{{color:#a01825}}.medium{{color:#805000}}.low{{color:#28633b}}small{{color:#526176}}
.snapshot{{border-left:4px solid #3876c8;padding:.6rem 1rem}}
</style></head><body><header><h1>Network Security Assessment</h1>
<div class="cards"><div class="card">Target: {target}</div><div class="card">Hosts: {host_count}</div>
<div class="card">Network risk: {risk_score}/100 ({risk_label})</div>
<div class="card">Status: {status}</div></div>
<p>Scan ID: {scan_id}<br>Started: {started_at}<br>Finished: {finished_at}</p>
<p class="snapshot">Results are a point-in-time snapshot; network state can change.
Findings are indicators, not proof of exploitability.</p>{errors}</header>{hosts}</body></html>""".format(
        target=esc(scan["target"]), host_count=len(scan["hosts"]),
        risk_score=scan["risk_score"], risk_label=esc(scan["risk_label"]),
        status=esc(scan["status"]), scan_id=esc(scan["scan_id"]),
        started_at=esc(scan["started_at"]), finished_at=esc(scan["finished_at"]),
        errors="<ul>{}</ul>".format(errors) if errors else "",
        hosts="".join(sections),
    )


def write_reports(scan: Dict[str, Any], output_dir: Path) -> None:
    """Write JSON and self-contained HTML reports to the scan folder."""
    (output_dir / "report.json").write_text(
        json.dumps(scan, indent=2, sort_keys=True), encoding="utf-8"
    )
    (output_dir / "report.html").write_text(render_html(scan), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    """Create CLI parser for the MVP interface."""
    parser = argparse.ArgumentParser(
        description="Authorized Nmap network assessment; discovery and inventory only."
    )
    parser.add_argument("target", help="One IP address, hostname, or CIDR target.")
    parser.add_argument(
        "--i-have-permission", action="store_true",
        help="Confirm you own or have written authorization to assess this target.",
    )
    parser.add_argument("--vuln", action="store_true", help="Run Nmap's vuln NSE scripts.")
    parser.add_argument("--full", action="store_true", help="Scan all TCP ports instead of the top 1000.")
    parser.add_argument("--allow-large", action="store_true", help="Allow CIDR ranges broader than /16.")
    parser.add_argument("--out", type=Path, default=Path("scans"), help="Output root (default: scans/).")
    parser.add_argument("--timeout", type=int, default=900, help="Per-phase timeout in seconds.")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run a single authorized assessment and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be a positive number of seconds.")
    try:
        scan = run_assessment(
            args.target, args.out, args.i_have_permission, args.vuln,
            args.full, args.allow_large, args.timeout
        )
    except (AssessmentError, OSError) as error:
        print("Error: {}".format(error), file=sys.stderr)
        return 2
    print("\nScan {}: {} | {} hosts | Risk {}/100 ({})".format(
        scan["scan_id"], scan["status"], len(scan["hosts"]),
        scan["risk_score"], scan["risk_label"]
    ))
    print("Reports: {}".format(scan["output_dir"]))
    for host in scan["hosts"]:
        open_ports = ", ".join(str(item["number"]) for item in host["ports"]) or "-"
        print("{}  open ports: {}  risk: {}/100".format(
            host["address"], open_ports, host["risk_score"]
        ))
    return 1 if scan["status"] == "failed" else 0


if __name__ == "__main__":
    sys.exit(main())
