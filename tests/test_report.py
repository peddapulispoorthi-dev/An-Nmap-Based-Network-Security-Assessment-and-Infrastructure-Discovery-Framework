import json
from pathlib import Path

from nmapfw.models import Finding, Host, Port, Scan
from nmapfw.report import generate_reports, render_html
from nmapfw.topology import topology_data


def test_report_files_and_content(tmp_path):
    scan = Scan(
        ["192.0.2.10"],
        scan_id="report-test",
        hosts=[
            Host(
                "192.0.2.10",
                ports=[Port(80, "tcp", "open", "http")],
                findings=[
                    Finding(
                        "Exposed web service",
                        "medium",
                        "Observed issue",
                        "Restrict access",
                        host="192.0.2.10",
                        port=80,
                    )
                ],
                traceroute=[{"ttl": 1, "ip": "192.0.2.1", "hostname": "gateway", "rtt": "1.1"}],
            )
        ],
    )
    directory = generate_reports(scan, tmp_path)
    expected = ["report.json", "report.csv", "report.md", "report.html"]
    assert all((directory / filename).is_file() for filename in expected)
    assert "point-in-time snapshot" in (directory / "report.md").read_text()
    assert "Exposed web service" in (directory / "report.html").read_text()
    assert json.loads((directory / "report.json").read_text())["hosts"][0]["address"] == "192.0.2.10"
    assert "192.0.2.10" in (directory / "report.csv").read_text()


def test_html_escapes_untrusted_values():
    scan = Scan(["<script>alert(1)</script>"], hosts=[Host("<img src=x>", hostnames=['<script>'])])
    html = render_html(scan)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "&lt;img src=x&gt;" in html


def test_topology_graph_from_trace():
    scan = Scan(
        [],
        hosts=[Host("192.0.2.10", traceroute=[{"ttl": 1, "ip": "192.0.2.1"}, {"ttl": 2, "ip": "192.0.2.2"}])],
    )
    graph = topology_data(scan)
    assert len(graph["nodes"]) == 3
    assert graph["links"] == [
        {"source": "192.0.2.1", "target": "192.0.2.2"},
        {"source": "192.0.2.2", "target": "192.0.2.10"},
    ]
