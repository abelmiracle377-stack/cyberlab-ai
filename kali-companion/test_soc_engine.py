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


class IncidentCorrelationTests(unittest.TestCase):
    def test_alerts_sharing_a_host_group_into_one_incident(self):
        events = (auth_failures("web01", "45.33.32.156", "root", 6)
                  + [{"type": "auth_success", "host": "web01", "src_ip": "45.33.32.156", "user": "root"}]
                  + [{"type": "listening_socket", "host": "web01", "port": 4444}])
        out = se.analyze(events)
        self.assertGreaterEqual(out["alert_count"], 3)
        # All three alerts share host web01 -> a single incident.
        self.assertEqual(out["incident_count"], 1)
        incident = out["incidents"][0]
        self.assertEqual(incident["severity"], "critical")
        self.assertEqual(incident["alert_count"], out["alert_count"])
        self.assertIn("Credential Access", incident["tactics"])
        self.assertIn("Command and Control", incident["tactics"])

    def test_unrelated_alerts_stay_separate(self):
        events = ([{"type": "listening_socket", "host": "web01", "port": 4444}]
                  + [{"type": "listening_socket", "host": "db02", "port": 31337}])
        out = se.analyze(events)
        self.assertEqual(out["incident_count"], 2)

    def test_incidents_ranked_by_score(self):
        events = (auth_failures("a", "10.0.0.1", "root", 6)
                  + [{"type": "listening_socket", "host": "b", "port": 4444}])
        incidents = se.analyze(events)["incidents"]
        self.assertEqual([i["score"] for i in incidents], sorted((i["score"] for i in incidents), reverse=True))

    def test_empty_has_no_incidents(self):
        self.assertEqual(se.group_incidents([]), [])


class ThreatIntelTests(unittest.TestCase):
    def test_known_bad_ip_raises_critical_alert(self):
        events = [{"type": "network_connection", "host": "web01", "src_ip": "45.33.32.156", "dst_ip": "203.0.113.9"}]
        out = se.analyze(events, {"indicators": {"ips": ["45.33.32.156"]}})
        alert = next(a for a in out["alerts"] if a["rule"] == "known_indicator")
        self.assertEqual(alert["severity"], "critical")
        self.assertEqual(alert["entities"]["indicator_type"], "ip")
        self.assertIn("block_ip", [a["action"] for a in alert["recommended_actions"]])

    def test_known_bad_hash_and_domain(self):
        events = [
            {"type": "process", "host": "wks3", "details": {"sha256": "ABCDEF"}},
            {"type": "network_connection", "host": "wks3", "domain": "Evil.Example"},
        ]
        out = se.analyze(events, {"indicators": {"hashes": ["abcdef"], "domains": ["evil.example"]}})
        rules = [a for a in out["alerts"] if a["rule"] == "known_indicator"]
        types = {a["entities"]["indicator_type"] for a in rules}
        self.assertEqual(types, {"hash", "domain"})  # case-insensitive match

    def test_no_indicators_no_alert(self):
        events = [{"type": "network_connection", "host": "web01", "src_ip": "45.33.32.156"}]
        out = se.analyze(events)
        self.assertFalse(any(a["rule"] == "known_indicator" for a in out["alerts"]))


class SuppressionTests(unittest.TestCase):
    def test_drop_suppression_removes_matching_alert(self):
        events = [{"type": "listening_socket", "host": "scanner", "port": 4444}]
        base = se.analyze(events)
        self.assertEqual(base["alert_count"], 1)
        tuned = se.analyze(events, {"suppressions": [{"rule": "suspicious_listening_port", "host": "scanner"}]})
        self.assertEqual(tuned["alert_count"], 0)
        self.assertEqual(tuned["suppressed_count"], 1)

    def test_cap_suppression_downgrades_severity(self):
        events = [{"type": "listening_socket", "host": "lab", "port": 4444}]
        tuned = se.analyze(events, {"suppressions": [
            {"host": "lab", "action": "cap", "max_severity": "low"}]})
        alert = tuned["alerts"][0]
        self.assertEqual(alert["severity"], "low")
        self.assertEqual(alert["suppressed"], "capped")

    def test_expired_suppression_is_ignored(self):
        events = [{"type": "listening_socket", "host": "scanner", "port": 4444}]
        tuned = se.analyze(events, {"now": "2026-11-20T00:00:00Z", "suppressions": [
            {"rule": "suspicious_listening_port", "host": "scanner", "expires": "2026-11-19T00:00:00Z"}]})
        self.assertEqual(tuned["alert_count"], 1)  # suppression already expired

    def test_overbroad_suppression_with_no_selector_ignored(self):
        events = [{"type": "listening_socket", "host": "scanner", "port": 4444}]
        tuned = se.analyze(events, {"suppressions": [{"action": "drop"}]})
        self.assertEqual(tuned["alert_count"], 1)  # refuses to drop everything


if __name__ == "__main__":
    unittest.main()
