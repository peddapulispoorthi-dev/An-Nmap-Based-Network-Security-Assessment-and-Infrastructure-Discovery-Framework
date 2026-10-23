import unittest
from pathlib import Path

import nmap_framework


class FindingAnalysisTests(unittest.TestCase):
    def test_nse_and_outdated_service_findings_are_prioritized(self):
        fixture = Path(__file__).parent / "fixtures" / "nse-output.xml"
        hosts = nmap_framework._parse_nmap_xml(fixture)
        score, label = nmap_framework.analyze_hosts(hosts)
        findings = hosts[0]["findings"]

        self.assertEqual([item["severity"] for item in findings], ["High", "High"])
        self.assertEqual(findings[0]["cves"], ["CVE-2021-41773"])
        self.assertGreater(score, 0)
        self.assertEqual(label, "High")

    def test_telnet_has_actionable_remediation(self):
        hosts = [{
            "address": "192.0.2.1",
            "ports": [{
                "number": 23,
                "protocol": "tcp",
                "state": "open",
                "service": "telnet",
                "product": "",
                "version": "",
                "extra_info": "",
                "scripts": {},
            }],
            "findings": [],
            "risk_score": 0,
        }]
        nmap_framework.analyze_hosts(hosts)
        self.assertIn("Disable Telnet", hosts[0]["findings"][0]["remediation"])


if __name__ == "__main__":
    unittest.main()
