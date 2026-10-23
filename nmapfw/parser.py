"""Parse Nmap's XML output into framework models."""

from pathlib import Path
from xml.etree import ElementTree

from nmapfw.models import Host, Port, Scan


def parse_nmap_xml(source: str | Path, targets: list[str] | None = None) -> Scan:
    """Parse Nmap XML from a file path or XML string into a scan result."""
    if isinstance(source, Path):
        root = ElementTree.parse(source).getroot()
    elif source.lstrip().startswith("<"):
        root = ElementTree.fromstring(source)
    else:
        root = ElementTree.parse(source).getroot()
    scan = Scan(targets=targets or [])
    scan.started_at = root.get("startstr", scan.started_at)
    hosts: list[Host] = []
    for host_node in root.findall("host"):
        status_node = host_node.find("status")
        address_nodes = host_node.findall("address")
        ip_node = next(
            (node for node in address_nodes if node.get("addrtype") in {"ipv4", "ipv6"}),
            None,
        )
        if ip_node is None:
            continue
        mac_node = next((node for node in address_nodes if node.get("addrtype") == "mac"), None)
        hostname_nodes = host_node.findall("./hostnames/hostname")
        ports: list[Port] = []
        for port_node in host_node.findall("./ports/port"):
            service_node = port_node.find("service")
            scripts = {
                node.get("id", "unknown"): node.get("output", "")
                for node in port_node.findall("script")
            }
            state_node = port_node.find("state")
            ports.append(
                Port(
                    number=int(port_node.get("portid", "0")),
                    protocol=port_node.get("protocol", ""),
                    state=state_node.get("state", "unknown") if state_node is not None else "unknown",
                    service=service_node.get("name", "") if service_node is not None else "",
                    product=service_node.get("product", "") if service_node is not None else "",
                    version=service_node.get("version", "") if service_node is not None else "",
                    extra_info=service_node.get("extrainfo", "") if service_node is not None else "",
                    scripts=scripts,
                )
            )
        os_matches = [
            {
                "name": match.get("name", ""),
                "accuracy": int(match.get("accuracy", "0")),
                "family": "",
            }
            for match in host_node.findall("./os/osmatch")
        ]
        for match, match_node in zip(os_matches, host_node.findall("./os/osmatch")):
            os_class = match_node.find("osclass")
            if os_class is not None:
                match["family"] = os_class.get("osfamily", "")
        hops: list[dict[str, str | int]] = []
        for hop in host_node.findall("./trace/hop"):
            hops.append(
                {
                    "ttl": int(hop.get("ttl", "0")),
                    "ip": hop.get("ipaddr", ""),
                    "hostname": hop.get("host", ""),
                    "rtt": hop.get("rtt", ""),
                }
            )
        hosts.append(
            Host(
                address=ip_node.get("addr", ""),
                status=status_node.get("state", "unknown") if status_node is not None else "unknown",
                mac_address=mac_node.get("addr", "") if mac_node is not None else "",
                vendor=mac_node.get("vendor", "") if mac_node is not None else "",
                hostnames=[node.get("name", "") for node in hostname_nodes if node.get("name")],
                ports=ports,
                os_matches=os_matches,
                traceroute=hops,
            )
        )
    scan.hosts = hosts
    finished = root.find("./runstats/finished")
    if finished is not None:
        scan.finished_at = finished.get("timestr", "")
    return scan
