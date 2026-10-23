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
    old_ports = {
        (host.address, port.protocol, port.number): port
        for host in older.hosts
        for port in host.ports
    }
    new_ports = {
        (host.address, port.protocol, port.number): port
        for host in newer.hosts
        for port in host.ports
    }
    for (address, protocol, number), port in new_ports.items():
        previous = old_ports.get((address, protocol, number))
        if port.state.lower() == "open" and (
            previous is None or previous.state.lower() != "open"
        ):
            result["newly_opened_ports"].append(
                {"host": address, "protocol": protocol, "port": number, "service": port.service}
            )
        elif previous and port.state.lower() == "open" and (
            previous.service,
            previous.product,
            previous.version,
        ) != (port.service, port.product, port.version):
            result["changed_services"].append(
                {
                    "host": address,
                    "protocol": protocol,
                    "port": number,
                    "before": asdict(previous),
                    "after": asdict(port),
                }
            )
    for (address, protocol, number), port in old_ports.items():
        current = new_ports.get((address, protocol, number))
        if port.state.lower() == "open" and (current is None or current.state.lower() != "open"):
            result["closed_ports"].append(
                {"host": address, "protocol": protocol, "port": number}
            )

    old_findings = {
        _finding_key(finding): finding for host in older.hosts for finding in host.findings
    }
    new_findings = {
        _finding_key(finding): finding for host in newer.hosts for finding in host.findings
    }
    key_order = lambda item: (
        item[0],
        item[1],
        -1 if item[2] is None else item[2],
        item[3],
    )
    result["new_findings"] = [
        asdict(new_findings[key])
        for key in sorted(new_findings.keys() - old_findings.keys(), key=key_order)
    ]
    result["resolved_findings"] = [
        asdict(old_findings[key])
        for key in sorted(old_findings.keys() - new_findings.keys(), key=key_order)
    ]
    return result
