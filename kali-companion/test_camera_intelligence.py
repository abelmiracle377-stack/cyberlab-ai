import unittest
from unittest.mock import patch

from camera_intelligence import build_rtsp_url, public_webcam_directory, validate_camera_host, validate_lan_network


class CameraIntelligenceTests(unittest.TestCase):
    def test_accepts_private_lan_subnet(self):
        self.assertEqual(str(validate_lan_network("192.168.1.0/24")), "192.168.1.0/24")

    def test_rejects_public_or_oversized_network(self):
        for value in ("8.8.8.0/24", "10.0.0.0/8", "192.168.0.0/16"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_lan_network(value)

    def test_rejects_ipv6_for_lan_discovery(self):
        with self.assertRaises(ValueError):
            validate_lan_network("fd00::/64")

    def test_validates_single_host_not_url(self):
        self.assertEqual(validate_camera_host("192.168.1.20"), "192.168.1.20")
        with self.assertRaises(ValueError):
            validate_camera_host("rtsp://192.168.1.20/live")


    def test_detect_private_lan_networks_parses_ip_output(self):
        completed = type("Completed", (), {"stdout": "2: wlan0 inet 192.168.1.23/24 scope global wlan0\n"})()
        with patch("camera_intelligence.shutil.which", return_value="/usr/sbin/ip"):
            with patch("camera_intelligence.subprocess.run", return_value=completed):
                from camera_intelligence import detect_private_lan_networks
                self.assertEqual(detect_private_lan_networks(), ["192.168.1.0/24"])

    def test_detect_private_lan_networks_ignores_public_interfaces(self):
        completed = type("Completed", (), {"stdout": "2: eth0 inet 98.97.76.185/24 scope global eth0\n"})()
        with patch("camera_intelligence.shutil.which", return_value="/usr/sbin/ip"):
            with patch("camera_intelligence.subprocess.run", return_value=completed):
                from camera_intelligence import detect_private_lan_networks
                self.assertEqual(detect_private_lan_networks(), [])

    def test_detect_private_lan_networks_caps_large_interface_at_24(self):
        completed = type("Completed", (), {"stdout": "2: eth0 inet 10.20.30.40/16 scope global eth0\n"})()
        with patch("camera_intelligence.shutil.which", return_value="/usr/sbin/ip"):
            with patch("camera_intelligence.subprocess.run", return_value=completed):
                from camera_intelligence import detect_private_lan_networks
                self.assertEqual(detect_private_lan_networks(), ["10.20.30.0/24"])

    def test_passwordless_rtsp_url(self):
        self.assertEqual(build_rtsp_url("192.168.1.20", 554, "/live"), "rtsp://192.168.1.20:554/live")

    def test_authenticated_rtsp_credentials_are_escaped(self):
        url = build_rtsp_url("camera.local", 8554, "/stream", "operator", "p@ss word")
        self.assertIn("operator:p%40ss%20word@", url)
        self.assertTrue(url.startswith("rtsp://"))

    def test_rejects_partial_credentials(self):
        with self.assertRaises(ValueError):
            build_rtsp_url("192.168.1.20", 554, "/live", "operator", "")

    def test_public_directory_only_lists_opt_in_sources(self):
        result = public_webcam_directory("Lagos")
        self.assertEqual(result["location_search"], "Lagos")
        self.assertGreaterEqual(len(result["directories"]), 3)
        self.assertIn("does not crawl public IP ranges", result["privacy_boundary"])


if __name__ == "__main__":
    unittest.main()
