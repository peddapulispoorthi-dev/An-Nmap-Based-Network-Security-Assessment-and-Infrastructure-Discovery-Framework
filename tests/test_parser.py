from pathlib import Path
from xml.etree.ElementTree import ParseError

import pytest

from nmapfw.parser import parse_nmap_xml

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_open_ports_os_and_traceroute():
    scan = parse_nmap_xml(FIXTURES / "open-ports.xml", ["192.0.2.0/24"])
    host = scan.hosts[0]
    assert host.address == "192.0.2.10"
    assert host.status == "up"
    assert host.vendor == "Example Vendor"
    assert host.hostnames == ["web.lab.example"]
    assert (host.ports[0].number, host.ports[0].service, host.ports[0].version) == (
        22,
        "ssh",
        "8.2",
    )
    assert host.os_matches[0]["accuracy"] == 96
    assert host.os_matches[0]["family"] == "Linux"
    assert host.traceroute[0]["ip"] == "192.0.2.1"


def test_parse_no_live_hosts():
    scan = parse_nmap_xml(FIXTURES / "no-live-hosts.xml")
    assert len(scan.hosts) == 1
    assert scan.hosts[0].status == "down"
    assert scan.hosts[0].ports == []


def test_parse_nse_output_and_missing_metadata():
    scan = parse_nmap_xml(FIXTURES / "nse-output.xml")
    port = scan.hosts[0].ports[0]
    assert port.scripts["vuln-test"].startswith("VULNERABLE")
    assert port.extra_info == ""


def test_malformed_xml_is_reported():
    with pytest.raises(ParseError):
        parse_nmap_xml("<nmaprun>")
