"""Rule-based findings and transparent risk scoring."""

import re
from collections.abc import Callable

from nmapfw.models import Finding, Host, Scan

SEVERITY_POINTS = {"critical": 35, "high": 25, "medium": 15, "low": 8, "info": 0}

RISKY_PORTS: dict[int, tuple[str, str, str]] = {
    21: ("high", "FTP may expose credentials or transfer data without encryption.", "Disable FTP or replace it with SFTP/FTPS; restrict access and require encryption."),
    23: ("high", "Telnet sends credentials and session data in clear text.", "Disable Telnet and use SSH with key-based authentication."),
    69: ("medium", "TFTP has no authentication and can expose or overwrite files.", "Disable TFTP or isolate it and restrict access to required hosts."),
    79: ("medium", "Finger can disclose user and system information.", "Disable the Finger service and filter the port."),
    111: ("medium", "RPC services can expose system procedures and expand attack surface.", "Disable unused RPC services and filter access to required peers."),
    135: ("medium", "Microsoft RPC endpoint mapping is exposed.", "Restrict RPC to trusted networks and apply current system updates."),
    139: ("high", "NetBIOS session service may expose file and host information.", "Disable NetBIOS where unnecessary and restrict access at the firewall."),
    161: ("high", "SNMP may disclose sensitive device configuration, especially with weak community strings.", "Disable SNMPv1/v2c where possible; use SNMPv3 and restrict management sources."),
    445: ("high", "SMB exposure can reveal shares and increases ransomware and lateral-movement risk.", "Restrict SMB to trusted networks, disable SMBv1, and patch affected systems."),
    512: ("high", "rexec is an insecure remote execution service.", "Disable rexec and use SSH for remote administration."),
    513: ("high", "rlogin may allow weakly authenticated remote access.", "Disable rlogin and use SSH with strong authentication."),
    514: ("high", "rsh provides insecure remote shell access.", "Disable rsh and use SSH with strong authentication."),
    1433: ("medium", "MSSQL database access is exposed on the network.", "Restrict database access to application hosts and enforce strong authentication and encryption."),
    1521: ("medium", "Oracle database listener is exposed on the network.", "Restrict listener access to trusted application hosts and keep Oracle patched."),
    2049: ("high", "NFS may expose mounted files or sensitive data.", "Restrict NFS exports and firewall access to explicitly trusted systems."),
    3306: ("medium", "MySQL database access is exposed on the network.", "Bind MySQL to required interfaces and restrict access to application hosts."),
    3389: ("high", "RDP is exposed to network login attempts and remote access.", "Restrict RDP through VPN or allowlists, enforce MFA, and keep systems patched."),
    5432: ("medium", "PostgreSQL database access is exposed on the network.", "Restrict PostgreSQL to trusted application hosts and require strong authentication."),
    5900: ("high", "VNC remote desktop access is exposed.", "Disable VNC when unused; otherwise tunnel it through an authenticated VPN or SSH."),
    6379: ("high", "Redis may allow unauthenticated data access or modification if misconfigured.", "Bind Redis to trusted interfaces, require authentication, and firewall the port."),
    9200: ("high", "Elasticsearch API may expose index data or administrative operations.", "Require authentication and TLS; restrict access to trusted application hosts."),
    27017: ("high", "MongoDB may expose databases if authentication or network controls are weak.", "Enable authentication and TLS, and restrict access to trusted clients."),
}

_VERSION_RULES: tuple[tuple[str, tuple[int, ...], str, str], ...] = (
    (
        "openssh",
        (7, 4),
        "medium",
        "OpenSSH versions before 7.4 are outdated and may lack important security fixes.",
    ),
    (
        "apache httpd",
        (2, 4, 50),
        "high",
        "Apache HTTP Server versions before 2.4.50 are outdated; version 2.4.49 had a known path traversal issue.",
    ),
    (
        "vsftpd",
        (3, 0, 3),
        "medium",
        "vsftpd versions before 3.0.3 are outdated and should be upgraded.",
    ),
)
_VERSION_PATTERN = re.compile(r"(?<!\d)(\d+(?:\.\d+){1,3})")
_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def _version_tuple(text: str) -> tuple[int, ...] | None:
    match = _VERSION_PATTERN.search(text)
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _is_older(version: tuple[int, ...], threshold: tuple[int, ...]) -> bool:
    width = max(len(version), len(threshold))
    return version + (0,) * (width - len(version)) < threshold + (0,) * (width - len(threshold))


def analyze_host(host: Host) -> Host:
    """Populate a host with rule-based findings and a 0-100 risk score."""
    findings: list[Finding] = []
    for port in host.ports:
        if port.state.lower() != "open":
            continue
        rule = RISKY_PORTS.get(port.number)
        if rule:
            severity, explanation, remediation = rule
            findings.append(
                Finding(
                    title=f"Exposed {port.service or 'service'} port {port.number}",
                    severity=severity,
                    description=explanation,
                    remediation=remediation,
                    host=host.address,
                    port=port.number,
                )
            )
        service_text = f"{port.product} {port.service}".lower()
        version = _version_tuple(port.version)
        if version:
            for product, threshold, severity, explanation in _VERSION_RULES:
                if product in service_text and _is_older(version, threshold):
                    findings.append(
                        Finding(
                            title=f"Outdated {port.product or port.service} version {port.version}",
                            severity=severity,
                            description=explanation,
                            remediation="Upgrade to a currently supported release and verify vendor security advisories.",
                            host=host.address,
                            port=port.number,
                        )
                    )
        for script_id, output in port.scripts.items():
            if "vulnerable" not in output.lower() or "not vulnerable" in output.lower():
                continue
            cves = sorted({item.upper() for item in _CVE_PATTERN.findall(output)})
            findings.append(
                Finding(
                    title=f"NSE reported a vulnerability ({script_id})",
                    severity="high",
                    description=output,
                    remediation="Review the referenced advisory, patch or mitigate the affected service, and rescan.",
                    host=host.address,
                    port=port.number,
                    cves=cves,
                )
            )
    host.findings = findings
    host.risk_score = min(
        100,
        sum(SEVERITY_POINTS.get(finding.severity.lower(), 0) for finding in findings),
    )
    return host


def risk_label(score: int) -> str:
    """Map a 0-100 risk score to a readable label."""
    if score < 20:
        return "Low"
    if score < 40:
        return "Medium"
    if score < 70:
        return "High"
    return "Critical"


def analyze_scan(scan: Scan) -> Scan:
    """Analyze every host and assign an average network risk score and label."""
    for host in scan.hosts:
        analyze_host(host)
    scan.risk_score = (
        round(sum(host.risk_score for host in scan.hosts) / len(scan.hosts)) if scan.hosts else 0
    )
    scan.risk_label = risk_label(scan.risk_score)
    return scan
