import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import nmap_framework as framework


ROOT = Path(__file__).parent


class TargetValidationTests(unittest.TestCase):
    def test_accepts_ip_hostname_and_bounded_cidr(self):
        self.assertEqual(framework.validate_target("192.0.2.10"), "192.0.2.10")
        self.assertEqual(framework.validate_target("SCANME.NMAP.ORG"), "scanme.nmap.org")
        self.assertEqual(framework.validate_target("192.0.2.4/24"), "192.0.2.0/24")

    def test_rejects_bad_or_broad_targets(self):
        for target in ("", "-sn", "192.0.2.1; whoami", "192.0.0.0/8"):
            with self.subTest(target=target):
                with self.assertRaises(framework.AssessmentError):
                    framework.validate_target(target)

    def test_authorization_is_required_before_any_scan_work(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(framework.AssessmentError, "pass --i-have-permission"):
                framework.run_assessment(
                    "192.0.2.1", Path(directory) / "scans", permission=False
                )
            self.assertFalse((Path(directory) / "scans").exists())


class ParserAndAnalyzerTests(unittest.TestCase):
    def test_parses_fixture_and_prioritizes_risky_open_ports(self):
        parsed = framework._parse_nmap_xml(ROOT / "fixtures" / "open-ports.xml")
        self.assertEqual(parsed[0]["address"], "192.0.2.10")
        self.assertEqual(parsed[0]["mac"], "00:11:22:33:44:55")
        self.assertEqual(parsed[0]["vendor"], "Example Vendor")
        self.assertEqual(parsed[0]["hostnames"], ["web.lab.example"])
        parsed[0]["ports"].append({
            "number": 23, "protocol": "tcp", "state": "open", "service": "telnet",
            "product": "", "version": "", "extra_info": "", "scripts": {},
        })
        score, label = framework.analyze_hosts(parsed)
        self.assertEqual(score, 25)
        self.assertEqual(label, "Medium")
        self.assertIn("Disable Telnet", parsed[0]["findings"][0]["remediation"])

    def test_extracts_nse_cve_and_ignores_negative_script(self):
        parsed = framework._parse_nmap_xml(ROOT / "fixtures" / "nse-output.xml")
        port = parsed[0]["ports"][0]
        port["scripts"]["negative"] = "NOT VULNERABLE"
        framework.analyze_hosts(parsed)
        self.assertEqual(len(parsed[0]["findings"]), 2)
        finding = next(item for item in parsed[0]["findings"] if "NSE" in item["title"])
        self.assertEqual(finding["cves"], ["CVE-2021-41773"])

    def test_empty_discovery_fixture_is_supported(self):
        parsed = framework._parse_nmap_xml(ROOT / "fixtures" / "no-live-hosts.xml")
        self.assertEqual(parsed[0]["status"], "down")
        self.assertEqual(parsed[0]["ports"], [])
        self.assertEqual(framework.analyze_hosts(parsed), (0, "Low"))

    def test_malformed_nmap_xml_returns_readable_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "malformed.xml"
            path.write_text("<nmaprun>", encoding="utf-8")
            with self.assertRaisesRegex(framework.AssessmentError, "Could not parse Nmap XML"):
                framework._parse_nmap_xml(path)


class ScanAndReportTests(unittest.TestCase):
    def test_phases_raw_xml_reports_and_audit(self):
        fixture = ROOT / "fixtures" / "open-ports.xml"
        calls = []

        def fake_phase(targets, arguments, xml_path, timeout):
            calls.append((list(targets), list(arguments), Path(xml_path).name, timeout))
            Path(xml_path).write_bytes(fixture.read_bytes())
            return framework._parse_nmap_xml(Path(xml_path))

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            with mock.patch.object(framework, "has_root_privileges", return_value=False):
                with mock.patch.object(framework, "_run_phase", side_effect=fake_phase):
                    scan = framework.run_assessment(
                        "192.0.2.10",
                        base / "scans",
                        permission=True,
                        include_vuln=True,
                        full=True,
                        audit_log=base / "logs" / "audit.log",
                    )
            scan_dir = Path(scan["output_dir"])
            self.assertEqual(scan["status"], "completed")
            self.assertTrue((scan_dir / "discovery.xml").is_file())
            self.assertTrue((scan_dir / "ports-services.xml").is_file())
            self.assertTrue((scan_dir / "nse-vuln.xml").is_file())
            self.assertTrue((scan_dir / "traceroute-192.0.2.10.xml").is_file())
            self.assertTrue((scan_dir / "report.json").is_file())
            self.assertTrue((scan_dir / "report.html").is_file())
            self.assertTrue((base / "logs" / "audit.log").is_file())
            self.assertEqual(calls[0][1], ["-sn"])
            self.assertIn("-p-", calls[1][1])
            self.assertEqual(calls[2][1], ["--script", "vuln"])
            self.assertEqual(calls[3][1], ["--traceroute", "-sn"])
            report = json.loads((scan_dir / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["target"], "192.0.2.10")
            self.assertIn("point-in-time snapshot", (scan_dir / "report.html").read_text(encoding="utf-8"))
            html_report = (scan_dir / "report.html").read_text(encoding="utf-8")
            self.assertIn("<td>22/tcp</td><td>open</td><td>ssh</td>", html_report)

    def test_discovery_down_hosts_do_not_receive_follow_up_scans(self):
        fixture = ROOT / "fixtures" / "no-live-hosts.xml"
        calls = []

        def fake_phase(targets, arguments, xml_path, timeout):
            calls.append((list(targets), list(arguments)))
            Path(xml_path).write_bytes(fixture.read_bytes())
            return framework._parse_nmap_xml(Path(xml_path))

        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(framework, "_run_phase", side_effect=fake_phase):
                scan = framework.run_assessment(
                    "192.0.2.0/24",
                    Path(directory) / "scans",
                    permission=True,
                    audit_log=Path(directory) / "logs" / "audit.log",
                )
        self.assertEqual(len(calls), 1)
        self.assertEqual(scan["hosts"], [])
        self.assertEqual(scan["risk_label"], "Low")

    def test_nmap_is_called_with_argument_list_without_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "scan.xml"
            captured = {}

            def fake_run(command, **kwargs):
                captured["command"] = command
                captured["kwargs"] = kwargs
                xml_path.write_text("<nmaprun/>", encoding="utf-8")
                return framework.subprocess.CompletedProcess(command, 0, "", "")

            with mock.patch.object(framework.shutil, "which", return_value="nmap"):
                with mock.patch.object(framework.subprocess, "run", side_effect=fake_run):
                    framework._run_phase(
                        ["192.0.2.1"], ["-sT", "--top-ports", "100"], xml_path, 60
                    )
            self.assertIsInstance(captured["command"], list)
            self.assertIn("-oX", captured["command"])
            self.assertFalse(captured["kwargs"]["shell"])
            self.assertEqual(captured["kwargs"]["timeout"], 60)

    def test_html_report_escapes_untrusted_data(self):
        scan = {
            "target": "<script>alert(1)</script>", "hosts": [], "errors": [],
            "risk_score": 0, "risk_label": "Low", "status": "completed",
            "scan_id": "test", "started_at": "", "finished_at": "",
        }
        report = framework.render_html(scan)
        self.assertNotIn("<script>alert(1)</script>", report)
        self.assertIn("&lt;script&gt;", report)


if __name__ == "__main__":
    unittest.main()
