import unittest
from pathlib import Path


class PublicReportTests(unittest.TestCase):
    def test_public_report_contains_assessment_but_redacts_route(self):
        report = (Path(__file__).parents[1] / "public" / "index.html").read_text(
            encoding="utf-8"
        )
        self.assertIn("scanme.nmap.org", report)
        self.assertIn("45.33.32.156", report)
        self.assertIn("Outdated Apache httpd", report)
        self.assertIn("Traceroute details have been omitted", report)
        self.assertNotIn("192.168.247.206", report)
        self.assertNotIn("ae1.r22.lax01", report)


if __name__ == "__main__":
    unittest.main()
