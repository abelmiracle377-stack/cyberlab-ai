"""Tests for the CyberSOC detection and triage engine."""
import unittest

import soc_engine as se


def auth_failures(host, src_ip, user, n):
    return [{"type": "auth_failure", "host": host, "src_ip": src_ip, "user": user,
             "timestamp": "2026-11-20T03:%02d:00Z" % i} for i in range(n)]


class DetectionRuleTests(unittest.TestCase):
    def test_brute_force_detected_above_threshold(self):
        out = se.analyze(auth_failures("web01", "10.0.0.9", "root", 6))
        alert = next(a for a in out["alerts"] if a["rule"] == "brute_force_login")
        self.assertEqual(alert["mitre"]["technique_id"], "T1110")
        self.assertEqual(alert["event_count"], 6)
        self.assertIn("block_ip", [a["action"] for a in alert["recommended_actions"]])

    def test_brute_force_below_threshold_is_silent(self):
        out = se.analyze(auth_failures("web01", "10.0.0.9", "root", 3))
        self.assertFalse(any(a["rule"] == "brute_force_login" for a in out["alerts"]))

    def test_public_source_raises_severity(self):
        private = se.analyze(auth_failures("web01", "10.0.0.9", "root", 6))
        public = se.analyze(auth_failures("web01", "45.33.32.156", "root", 6))
        pv = next(a for a in private["alerts"] if a["rule"] == "brute_force_login")["severity"]
        pb = next(a for a in public["alerts"] if a["rule"] == "brute_force_login")["severity"]
        self.assertEqual(pv, "medium")
        self.assertEqual(pb, "high")  # bumped because the source is a public IP

    def test_successful_login_after_failures_is_critical(self):
        events = auth_failures("web01", "45.33.32.156", "root", 6) + [
            {"type": "auth_success", "host": "web01", "src_ip": "45.33.32.156", "user": "root",
             "timestamp": "2026-11-20T03:30:00Z"}]
        out = se.analyze(events)
        alert = next(a for a in out["alerts"] if a["rule"] == "successful_login_after_failures")
        self.assertEqual(alert["severity"], "critical")
        self.assertEqual(out["highest_severity"], "critical")

    def test_implant_port_is_critical(self):
        out = se.analyze([{"type": "listening_socket", "host": "h", "port": 4444, "process": "nc"}])
        alert = out["alerts"][0]
        self.assertEqual(alert["rule"], "suspicious_listening_port")
        self.assertEqual(alert["severity"], "critical")
        self.assertEqual(alert["mitre"]["technique_id"], "T1571")

    def test_exposed_sensitive_service(self):
        out = se.analyze([{"type": "listening_socket", "host": "h", "port": 23,
                           "details": {"address": "0.0.0.0"}}])
        alert = next(a for a in out["alerts"] if a["rule"] == "exposed_sensitive_service")
        self.assertEqual(alert["severity"], "high")  # Telnet
        self.assertIn("Telnet", alert["title"])

    def test_bound_to_localhost_is_not_flagged(self):
        out = se.analyze([{"type": "listening_socket", "host": "h", "port": 3306,
                           "details": {"address": "127.0.0.1"}}])
        self.assertFalse(any(a["rule"] == "exposed_sensitive_service" for a in out["alerts"]))

    def test_privileged_external_login(self):
        out = se.analyze([{"type": "auth_success", "host": "h", "user": "root", "src_ip": "45.33.32.156"}])
        alert = next(a for a in out["alerts"] if a["rule"] == "privileged_external_login")
        self.assertEqual(alert["severity"], "high")
        self.assertEqual(alert["mitre"]["technique_id"], "T1078.003")

    def test_port_scan(self):
        events = [{"type": "network_connection", "host": "h", "src_ip": "10.0.0.5", "dst_port": p}
                  for p in range(20, 40)]
        out = se.analyze(events)
        alert = next(a for a in out["alerts"] if a["rule"] == "port_scan")
        self.assertEqual(alert["mitre"]["technique_id"], "T1046")

    def test_siem_passthrough_keeps_severity(self):
        out = se.analyze([{"type": "siem_alert", "source": "wazuh", "severity": "critical",
                           "message": "rootkit detected", "host": "h"}])
        alert = out["alerts"][0]
        self.assertEqual(alert["rule"], "siem_alert")
        self.assertEqual(alert["severity"], "critical")

    def test_alert_ids_are_stable_for_dedup(self):
        a = se.analyze(auth_failures("web01", "10.0.0.9", "root", 6))["alerts"][0]["id"]
        b = se.analyze(auth_failures("web01", "10.0.0.9", "root", 6))["alerts"][0]["id"]
        self.assertEqual(a, b)

    def test_ranked_by_score_and_summary(self):
        events = (auth_failures("web01", "45.33.32.156", "root", 6)
                  + [{"type": "auth_success", "host": "web01", "src_ip": "45.33.32.156", "user": "root"}]
                  + [{"type": "listening_socket", "host": "web01", "port": 4444}])
        out = se.analyze(events)
        scores = [a["score"] for a in out["alerts"]]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual(sum(out["by_severity"].values()), out["alert_count"])

    def test_rejects_non_list(self):
        with self.assertRaisesRegex(ValueError, "must be a list"):
            se.analyze({"not": "a list"})


if __name__ == "__main__":
    unittest.main()
