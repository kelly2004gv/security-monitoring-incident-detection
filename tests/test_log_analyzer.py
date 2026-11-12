import unittest

from datetime import datetime, timezone

from src.log_analyzer import detect_threats


class TestSecurityAnalyzer(unittest.TestCase):

    def create_log(self, minute, result):
        return {
            "timestamp": datetime(
                2026, 11, 1, 9, minute,
                tzinfo=timezone.utc
            ),
            "username": "employee1",
            "source_ip": "192.168.1.10",
            "event": "login",
            "result": result
        }

    def test_brute_force_detection(self):
        logs = [
            self.create_log(0, "failed"),
            self.create_log(2, "failed"),
            self.create_log(3, "failed"),
            self.create_log(5, "failed"),
            self.create_log(7, "failed")
        ]

        alerts = detect_threats(logs)

        rules = {alert["rule"] for alert in alerts}

        self.assertIn("RULE-001", rules)
        self.assertIn("RULE-002", rules)

    def test_success_after_failures(self):
        logs = [
            self.create_log(0, "failed"),
            self.create_log(1, "failed"),
            self.create_log(2, "failed"),
            self.create_log(3, "failed"),
            self.create_log(4, "failed"),
            self.create_log(5, "success")
        ]

        alerts = detect_threats(logs)

        rules = {alert["rule"] for alert in alerts}

        self.assertIn("RULE-003", rules)

    def test_normal_login(self):
        logs = [
            self.create_log(0, "success")
        ]

        alerts = detect_threats(logs)

        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()