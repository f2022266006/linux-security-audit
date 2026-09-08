import json
import tempfile
import unittest
from pathlib import Path

from linux_security_audit import (Finding, audit_sample, parse_failed_logins,
                                  parse_ss_listeners, parse_sshd_config, rating,
                                  score, write_reports)


class AuditTests(unittest.TestCase):
    def test_listening_port_parser(self):
        text = "Netid State Local Address:Port\ntcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
        self.assertEqual(parse_ss_listeners(text), ["22"])

    def test_failed_login_parser(self):
        text = "Failed password for root\nok\npam: authentication failure\nInvalid user test"
        self.assertEqual(parse_failed_logins(text), 3)

    def test_sshd_parser_ignores_comments(self):
        values = parse_sshd_config("# PermitRootLogin yes\nPermitRootLogin no\nPasswordAuthentication no\n")
        self.assertEqual(values["permitrootlogin"], "no")

    def test_score_has_floor(self):
        items = [Finding("x", "CRITICAL", "x", "x", "x", 80), Finding("y", "CRITICAL", "y", "y", "y", 80)]
        self.assertEqual(score(items), 0)

    def test_rating_boundaries(self):
        self.assertEqual(rating(85), "Good")
        self.assertEqual(rating(65), "Needs attention")
        self.assertEqual(rating(64), "High risk")

    def test_sample_audit_returns_all_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.json"
            source = Path("sample_data/sample_host.json")
            path.write_text(source.read_text(), encoding="utf-8")
            findings = audit_sample(path)
            self.assertEqual(len(findings), 11)
            self.assertEqual({x.check for x in findings}, {"permissions", "suid", "services", "ports", "failed_logins", "password_policy", "firewall", "admins", "world_writable", "updates", "ssh"})

    def test_reports_are_valid(self):
        items = [Finding("firewall", "PASS", "Firewall", "active", "none", 0)]
        with tempfile.TemporaryDirectory() as directory:
            text_path, json_path = write_reports(items, Path(directory), "sample")
            self.assertIn("Score: 100/100", text_path.read_text())
            self.assertEqual(json.loads(json_path.read_text())["score"], 100)


if __name__ == "__main__":
    unittest.main()
