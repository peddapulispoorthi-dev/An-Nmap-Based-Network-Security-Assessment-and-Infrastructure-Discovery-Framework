from nmapfw.diff import compare_scans
from nmapfw.models import Finding, Host, Port, Scan
from nmapfw.storage import get_scan, list_scans, save_scan


def test_sqlite_round_trip_and_normalized_records(tmp_path):
    database = tmp_path / "history.sqlite3"
    scan = Scan(
        ["192.0.2.10"],
        scan_id="scan-one",
        hosts=[
            Host(
                "192.0.2.10",
                ports=[Port(22, "tcp", "open", "ssh", "OpenSSH", "8.2")],
                findings=[Finding("SSH exposure", "low", "Observed", "Restrict access", host="192.0.2.10", port=22)],
            )
        ],
    )
    save_scan(scan, database)
    restored = get_scan("scan-one", database)
    assert restored.hosts[0].ports[0].version == "8.2"
    assert restored.hosts[0].findings[0].title == "SSH exposure"
    assert list_scans(database)[0]["scan_id"] == "scan-one"


def test_diff_reports_host_ports_services_and_findings():
    old = Scan(
        [],
        hosts=[
            Host(
                "192.0.2.10",
                ports=[
                    Port(22, "tcp", "open", "ssh", "OpenSSH", "8.2"),
                    Port(80, "tcp", "open", "http"),
                    Port(8080, "tcp", "open", "http-alt"),
                ],
                findings=[Finding("Old issue", "medium", "old", "fix", host="192.0.2.10", port=80)],
            ),
            Host(
                "192.0.2.20",
                findings=[Finding("Removed host issue", "low", "old host", "review", host="192.0.2.20")],
            ),
        ],
    )
    new = Scan(
        [],
        hosts=[
            Host(
                "192.0.2.10",
                ports=[
                    Port(22, "tcp", "open", "ssh", "OpenSSH", "9.0"),
                    Port(80, "tcp", "closed", "http"),
                    Port(443, "tcp", "open", "https"),
                ],
                findings=[Finding("New issue", "high", "new", "patch", host="192.0.2.10", port=443)],
            ),
            Host(
                "192.0.2.30",
                ports=[Port(8443, "tcp", "open", "https-alt")],
                findings=[Finding("New host issue", "low", "new host", "review", host="192.0.2.30")],
            ),
        ],
    )
    changes = compare_scans(old, new)
    assert changes["new_hosts"] == [{"address": "192.0.2.30"}]
    assert changes["removed_hosts"] == [{"address": "192.0.2.20"}]
    assert {(item["host"], item["port"]) for item in changes["newly_opened_ports"]} == {
        ("192.0.2.10", 443),
        ("192.0.2.30", 8443),
    }
    assert {(item["host"], item["port"]) for item in changes["closed_ports"]} == {
        ("192.0.2.10", 80),
        ("192.0.2.10", 8080),
    }
    assert changes["changed_services"][0]["after"]["version"] == "9.0"
    assert {item["title"] for item in changes["new_findings"]} == {"New issue", "New host issue"}
    assert {item["title"] for item in changes["resolved_findings"]} == {
        "Old issue",
        "Removed host issue",
    }
