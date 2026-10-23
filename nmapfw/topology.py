"""Convert host traceroutes into JSON-ready graph data."""

from nmapfw.models import Scan


def topology_data(scan: Scan) -> dict[str, list[dict[str, str | int]]]:
    """Build unique network nodes and directed links from traceroute hops."""
    nodes: dict[str, dict[str, str | int]] = {}
    links: set[tuple[str, str]] = set()
    for host in scan.hosts:
        previous = ""
        for hop in sorted(host.traceroute, key=lambda item: int(item.get("ttl", 0))):
            address = str(hop.get("ip", ""))
            if not address:
                continue
            nodes.setdefault(
                address,
                {
                    "id": address,
                    "label": str(hop.get("hostname") or address),
                    "kind": "hop",
                    "ttl": int(hop.get("ttl", 0)),
                },
            )
            if previous and previous != address:
                links.add((previous, address))
            previous = address
        destination = host.address
        nodes.setdefault(destination, {"id": destination, "label": destination, "kind": "host"})
        if previous and previous != destination:
            links.add((previous, destination))
    return {
        "nodes": list(nodes.values()),
        "links": [{"source": start, "target": end} for start, end in sorted(links)],
    }
