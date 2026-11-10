import unittest
from camera_exposure_defence import QUESTIONS, assess_camera_configuration, build_responsible_disclosure_template

class CameraExposureDefenceTests(unittest.TestCase):
    def answers(self, value="no"):
        return {key: value for key in QUESTIONS}

    def test_scored_assessment_is_labelled_self_reported(self):
        answers = self.answers()
        answers["internet_exposed"] = "yes"
        result = assess_camera_configuration({"model": "Example NVR"}, answers)
        self.assertGreater(result["risk_score"], 0)
        self.assertIn("not technical verification", result["assessment_basis"])

    def test_unknowns_require_verification(self):
        result = assess_camera_configuration({}, self.answers("unknown"))
        self.assertEqual(len(result["verification_required"]), len(QUESTIONS))
        self.assertEqual(result["findings"], [])

    def test_invalid_answer_rejected(self):
        answers = self.answers()
        answers["mfa"] = "maybe"
        with self.assertRaises(ValueError):
            assess_camera_configuration({}, answers)

    def test_missing_control_rejected(self):
        with self.assertRaises(ValueError):
            assess_camera_configuration({}, {"https": "yes"})

    def test_disclosure_template_is_careful(self):
        report = build_responsible_disclosure_template(
            {"model": "NVR-100"},
            [{"observation": "HTTPS disabled", "recommendation": "Enable HTTPS."}],
        )
        self.assertIn("NVR-100", report)
        self.assertIn("did not bypass authentication", report)
        self.assertIn("Enable HTTPS.", report)

if __name__ == "__main__":
    unittest.main()
