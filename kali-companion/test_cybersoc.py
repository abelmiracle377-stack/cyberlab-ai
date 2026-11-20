"""Tests for the autonomous CyberSOC cycle and its response policy."""
import unittest

import cybersoc


def implant_event():
    return [{"type": "listening_socket", "host": "h", "port": 4444, "process": "nc"}]


def brute_force_events():
    return [{"type": "auth_failure", "host": "h", "src_ip": "45.33.32.156", "user": "root",
             "timestamp": "2026-11-20T03:%02d:00Z" % i} for i in range(6)]


class RunCycleTests(unittest.TestCase):
    def test_safe_actions_run_destructive_escalated(self):
        calls = []

        def responder(action):
            calls.append(action["action"])
            return {"status": "ok"}

        report = cybersoc.run_cycle([implant_event], responder=responder)
        # Critical implant alert: capture_pcap (safe) runs; kill_process/isolate_host escalate.
        self.assertIn("capture_pcap", [a["action"] for a in report["actions_taken"]])
        self.assertNotIn("kill_process", [a["action"] for a in report["actions_taken"]])
        pending = report["escalations"][0]["pending_actions"]
        self.assertIn("kill_process", pending)
        self.assertIn("isolate_host", pending)

    def test_widening_policy_authorizes_destructive_action(self):
        calls = []

        def responder(action):
            calls.append(action["action"])
            return {"status": "ok"}

        policy = {"allowed_actions": cybersoc.SAFE_AUTO_ACTIONS | {"kill_process", "isolate_host"}}
        report = cybersoc.run_cycle([implant_event], responder=responder, policy=policy)
        self.assertIn("kill_process", calls)  # now authorized, so it ran

    def test_auto_response_disabled_takes_no_action(self):
        calls = []
        report = cybersoc.run_cycle([brute_force_events], responder=lambda a: calls.append(a),
                                    policy={"auto_response": False})
        self.assertEqual(report["actions_taken"], [])

    def test_below_auto_severity_does_not_act(self):
        # Exposed MySQL is medium; default auto_response_min_severity is high.
        def medium_event():
            return [{"type": "listening_socket", "host": "h", "port": 3306,
                     "details": {"address": "0.0.0.0"}}]
        report = cybersoc.run_cycle([medium_event], responder=lambda a: {"status": "ok"})
        self.assertEqual(report["actions_taken"], [])

    def test_source_error_is_contained(self):
        def boom():
            raise RuntimeError("telemetry down")
        report = cybersoc.run_cycle([boom, implant_event], responder=lambda a: {"status": "ok"})
        self.assertEqual(len(report["source_errors"]), 1)
        self.assertEqual(report["alert_count"], 1)  # the other source still produced an alert

    def test_summary_line(self):
        report = cybersoc.run_cycle([implant_event], responder=lambda a: {"status": "ok"})
        summary = cybersoc.summarize(report)
        self.assertIn("1 alerts", summary)
        self.assertIn("critical", summary)

    def test_action_failure_is_escalated(self):
        def responder(action):
            raise RuntimeError("responder broke")
        report = cybersoc.run_cycle([implant_event], responder=responder)
        self.assertTrue(any(e.get("reason") == "action_failed" for e in report["escalations"]))


if __name__ == "__main__":
    unittest.main()
