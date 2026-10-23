"""Repeatable scan phase orchestration with permission and audit gates."""

import os
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from nmapfw.analyzer import analyze_scan
from nmapfw.config import DEFAULT_AUDIT_LOG, DEFAULT_DATABASE, DEFAULT_SCAN_DIR, get_profile
from nmapfw.models import Host, Scan
from nmapfw.parser import parse_nmap_xml
from nmapfw.runner import NmapError, run_nmap
from nmapfw.storage import save_scan
from nmapfw.validate import require_permission, validate_targets

ProgressCallback = Callable[[str, str], None]
Runner = Callable[..., object]


def has_raw_socket_privileges() -> bool:
    """Return whether this process can use raw sockets for SYN/OS scanning."""
    return os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0


def _audit_scan(targets: list[str], audit_log: Path) -> None:
    """Append a timestamped, one-line record for an authorized scan."""
    audit_log.parent.mkdir(parents=True, exist_ok=True)
    with audit_log.open("a", encoding="utf-8") as log:
        log.write(f"{datetime.now(timezone.utc).isoformat()} targets={','.join(targets)}\n")


def _merge_hosts(destination: dict[str, Host], incoming: list[Host]) -> None:
    """Merge phase-specific details without losing earlier scan results."""
    for host in incoming:
        existing = destination.get(host.address)
        if existing is None:
            destination[host.address] = host
            continue
        if host.status != "unknown":
            existing.status = host.status
        if host.mac_address:
            existing.mac_address = host.mac_address
            existing.vendor = host.vendor
        existing.hostnames = list(dict.fromkeys(existing.hostnames + host.hostnames))
        ports_by_key = {(port.protocol, port.number): port for port in existing.ports}
        for port in host.ports:
            ports_by_key[(port.protocol, port.number)] = port
        existing.ports = list(ports_by_key.values())
        existing.os_matches = host.os_matches or existing.os_matches
        existing.traceroute = host.traceroute or existing.traceroute


def run_scan(
    targets: str | list[str],
    profile: str = "quick",
    *,
    permission: bool = False,
    allow_large: bool = False,
    include_vuln: bool = False,
    include_udp: bool = False,
    output_dir: str | Path | None = None,
    audit_log: str | Path = DEFAULT_AUDIT_LOG,
    database: str | Path = DEFAULT_DATABASE,
    progress_callback: ProgressCallback | None = None,
    runner: Runner = run_nmap,
) -> Scan:
    """Run the selected, authorized Nmap profile and return merged scan results."""
    require_permission(permission)
    validated_targets = validate_targets(targets, allow_large=allow_large)
    selected = get_profile(profile)
    scan = Scan(targets=validated_targets, profile=selected.name)
    scan_directory = Path(output_dir) if output_dir else DEFAULT_SCAN_DIR / scan.scan_id
    scan_directory.mkdir(parents=True, exist_ok=True)
    _audit_scan(validated_targets, Path(audit_log))
    callback = progress_callback or (lambda _phase, _state: None)
    phases: list[tuple[str, list[str]]] = []
    if selected.discovery:
        phases.append(("discovery", ["-sn"]))
    port_args = ["-sS" if has_raw_socket_privileges() else "-sT"]
    if selected.service_detection:
        port_args.append("-sV")
    port_args.extend(selected.port_selection.split())
    phases.append(("ports", port_args))
    if selected.os_detection:
        if has_raw_socket_privileges():
            phases.append(("os", ["-O"]))
        else:
            callback("os", "skipped (requires elevated privileges)")
    if selected.vulnerability_scripts or include_vuln:
        phases.append(("nse-vulnerability", ["--script", "vuln"]))
    if selected.traceroute:
        phases.append(("traceroute", ["--traceroute"]))
    if selected.udp or include_udp:
        phases.append(("udp", ["-sU", "--top-ports", "50"]))

    merged_hosts: dict[str, Host] = {}
    errors: list[str] = []
    for index, (phase_name, arguments) in enumerate(phases, start=1):
        callback(phase_name, f"started ({index}/{len(phases)})")
        xml_path = scan_directory / f"{index:02d}-{phase_name}.xml"
        try:
            runner(validated_targets, arguments, xml_path)
            phase_scan = parse_nmap_xml(xml_path, validated_targets)
            _merge_hosts(merged_hosts, phase_scan.hosts)
            callback(phase_name, "completed")
        except (NmapError, OSError, ValueError) as exc:
            message = str(exc)
            errors.append(f"{phase_name}: {message}")
            callback(phase_name, f"failed: {message}")

    scan.hosts = list(merged_hosts.values())
    scan.finished_at = datetime.now(timezone.utc).isoformat()
    if errors:
        scan.status = "partial" if scan.hosts else "failed"
        scan.error = "; ".join(errors)
    analyze_scan(scan)
    save_scan(scan, database)
    return scan
