from nmapfw.analyzer import analyze_scan, risk_label
from nmapfw.models import Host, Port, Scan


def test_risky_ports_and_version_findings_score():
    host = Host(
        "192.0.2.10",
        ports=[
            Port(23, "tcp", "open", "telnet"),
            Port(22, "tcp", "open", "ssh", "OpenSSH", "6.9"),
            Port(80, "tcp", "closed", "http", "Apache httpd", "2.4.49"),
        ],
    )
    scan = analyze_scan(Scan(["192.0.2.10"], hosts=[host]))
    assert [finding.severity for finding in host.findings] == ["high", "medium"]
    assert host.risk_score == 40
    assert scan.risk_score == 40
    assert scan.risk_label == "High"
    assert "Disable Telnet" in host.findings[0].remediation


def test_nse_findings_extract_cves_and_skip_negative_results():
    host = Host(
        "198.51.100.25",
        ports=[
            Port(
                443,
                "tcp",
                "open",
                scripts={
                    "check": "VULNERABLE: CVE-2021-41773 and cve-2024-12345",
                    "negative": "NOT VULNERABLE",
                },
            )
        ],
    )
    analyze_scan(Scan(["198.51.100.25"], hosts=[host]))
    assert len(host.findings) == 1
    assert host.findings[0].cves == ["CVE-2021-41773", "CVE-2024-12345"]


def test_risk_score_caps_and_empty_network_label():
    hosts = [Host(str(index), ports=[Port(445, "tcp", "open") for _ in range(5)]) for index in range(3)]
    scan = analyze_scan(Scan([], hosts=hosts))
    assert all(host.risk_score == 100 for host in hosts)
    assert scan.risk_score == 100
    assert scan.risk_label == "Critical"
    assert risk_label(0) == "Low"
    assert analyze_scan(Scan([])).risk_score == 0
