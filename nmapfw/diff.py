"""Compare scans and report changes in hosts, services, and findings."""

from dataclasses import asdict

from nmapfw.models import Finding, Host, Scan


def _finding_key(finding: Finding) -> tuple[str, str, int | None, tuple[str, ...]]:
    return (finding.host, finding.title, finding.port, tuple(sorted(finding.cves)))


def compare_scans(older: Scan, newer: Scan) -> dict[str, list[dict[str, object]]]:
    """Compare two scans and return host, port, service, and finding changes."""
    old_hosts = {host.address: host for host in older.hosts}
    new_hosts = {host.address: host for host in newer.hosts}
    old_addresses, new_addresses = set(old_hosts), set(new_hosts)
    result: dict[str, list[dict[str, object]]] = {
        "new_hosts": [{"address": address} for address in sorted(new_addresses - old_addresses)],
        "removed_hosts": [{"address": address} for address in sorted(old_addresses - new_addresses)],
        "newly_opened_ports": [],
        "closed_ports": [],
        "changed_services": [],
        "new_findings": [],
        "resolved_findings": [],
    }
    for address in sorted(old_addresses & new_addresses):
        before, after = old_hosts[address], new_hosts[address]
        old_ports = {(port.protocol, port.number): port for port in before.ports}
        new_ports = {(port.protocol, port.number): port for port in after.ports}
        for key, port in new_ports.items():
            previous = old_ports.get(key)
            if port.state.lower() == "open" and (
                previous is None or previous.state.lower() != "open"
            ):
                result["newly_opened_ports"].append(
                    {"host": address, "protocol": port.protocol, "port": port.number, "service": port.service}
                )
            elif previous and previous.state.lower() == "open" and port.state.lower() != "open":
                result["closed_ports"].append(
                    {"host": address, "protocol": port.protocol, "port": port.number}
                )
            elif previous and port.state.lower() == "open" and (
                previous.service,
                previous.product,
                previous.version,
            ) != (port.service, port.product, port.version):
                result["changed_services"].append(
                    {
                        "host": address,
                        "protocol": port.protocol,
                        "port": port.number,
                        "before": asdict(previous),
                        "after": asdict(port),
                    }
                )
        old_findings = {_finding_key(item): item for item in before.findings}
        new_findings = {_finding_key(item): item for item in after.findings}
        result["new_findings"].extend(
            asdict(new_findings[key])
            for key in sorted(
                new_findings.keys() - old_findings.keys(),
                key=lambda item: (item[0], item[1], -1 if item[2] is None else item[2], item[3]),
            )
        )
        result["resolved_findings"].extend(
            asdict(old_findings[key])
            for key in sorted(
                old_findings.keys() - new_findings.keys(),
                key=lambda item: (item[0], item[1], -1 if item[2] is None else item[2], item[3]),
            )
        )
    return result
