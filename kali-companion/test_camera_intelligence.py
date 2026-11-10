import unittest
import camera_intelligence
from unittest.mock import patch

from camera_intelligence import (build_rtsp_url, public_webcam_directory, validate_camera_host, validate_lan_network, validate_camera_on_detected_lan, validate_camera_port, detect_private_lan_interfaces)


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

    def test_detect_private_lan_interfaces_shows_wifi_ip_and_subnet(self):
        completed = type("Completed", (), {"stdout": "3: wlan0 inet 192.168.1.23/24 scope global wlan0\\n"})()
        with patch("camera_intelligence.shutil.which", return_value="/usr/sbin/ip"):
            with patch("camera_intelligence.subprocess.run", return_value=completed):
                result = detect_private_lan_interfaces()
        self.assertEqual(result[0]["interface"], "wlan0")
        self.assertEqual(result[0]["ipv4"], "192.168.1.23")
        self.assertEqual(result[0]["network"], "192.168.1.0/24")

    def test_camera_ip_must_match_kali_local_subnet(self):
        result = validate_camera_on_detected_lan("192.168.1.201", ["192.168.1.0/24"])
        self.assertEqual(result["matching_local_network"], "192.168.1.0/24")

    def test_camera_ip_outside_kali_subnet_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "not inside Kali"):
            validate_camera_on_detected_lan("192.168.2.201", ["192.168.1.0/24"])

    def test_public_camera_ip_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_camera_on_detected_lan("8.8.8.8", ["192.168.1.0/24"])

    def test_hostname_is_not_accepted_for_subnet_match(self):
        with self.assertRaisesRegex(ValueError, "private IPv4"):
            validate_camera_on_detected_lan("camera.local", ["192.168.1.0/24"])

    def test_camera_ipv6_matches_kali_ipv6_prefix(self):
        interfaces = [{"interface": "wlan0", "family": "IPv6", "ip": "fd12:3456:789a::10",
                       "network": "fd12:3456:789a::/64"}]
        result = validate_camera_on_detected_lan("fd12:3456:789a::201", interfaces)
        self.assertEqual(result["ip_version"], 6)
        self.assertEqual(result["kali_ip"], "fd12:3456:789a::10")
        self.assertIn("Your Kali IP address is fd12:3456:789a::10", result["message"])

    def test_camera_ipv6_outside_kali_prefix_is_rejected(self):
        interfaces = [{"interface": "wlan0", "family": "IPv6", "ip": "fd12:3456:789a::10",
                       "network": "fd12:3456:789a::/64"}]
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate_camera_on_detected_lan("fd12:3456:789b::201", interfaces)

    def test_camera_ipv4_and_ipv6_use_matching_family_only(self):
        interfaces = [{"interface": "wlan0", "family": "IPv4", "ip": "192.168.1.20",
                       "network": "192.168.1.0/24"}]
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate_camera_on_detected_lan("fd12:3456:789a::201", interfaces)

    def test_ipv6_rtsp_url_uses_bracketed_host(self):
        self.assertEqual(build_rtsp_url("fd12:3456:789a::201", 554, "/live"),
                         "rtsp://[fd12:3456:789a::201]:554/live")

    def test_camera_port_validation(self):
        self.assertEqual(validate_camera_port("554"), 554)
        with self.assertRaises(ValueError):
            validate_camera_port("70000")

    def test_passwordless_rtsp_url(self):
        self.assertEqual(build_rtsp_url("192.168.1.20", 554, "/live"), "rtsp://192.168.1.20:554/live")

    def test_authenticated_rtsp_credentials_are_escaped(self):
        url = build_rtsp_url("camera.local", 8554, "/stream", "operator", "p@ss word")
        self.assertIn("operator:p%40ss%20word@", url)
        self.assertTrue(url.startswith("rtsp://"))

    def test_rejects_partial_credentials(self):
        with self.assertRaises(ValueError):
            build_rtsp_url("192.168.1.20", 554, "/live", "operator", "")


    def test_public_webcam_search_builds_location_specific_links(self):
        with patch.object(camera_intelligence, "_windy_public_webcams", return_value={"status": "not_configured"}):
            result = camera_intelligence.public_webcam_directory("Texas")
        self.assertEqual(result["feature"], "location_specific_public_webcam_search")
        self.assertEqual(result["location_search"], "Texas")
        self.assertEqual(len(result["targeted_searches"]), 4)
        for item in result["targeted_searches"]:
            self.assertIn("Texas", item["search_url"])
        self.assertIn("does not enumerate arbitrary exposed CCTV", result["privacy_boundary"])

    def test_public_webcam_search_rejects_empty_location(self):
        with self.assertRaisesRegex(ValueError, "Enter a city"):
            camera_intelligence.public_webcam_directory("  ")

    def test_windy_catalogue_returns_structured_public_camera_pages(self):
        geocode = {"results": [{"name": "Austin", "admin1": "Texas", "country": "United States", "latitude": 30.2672, "longitude": -97.7431}]}
        webcams = {"webcams": [{
            "id": 12345, "title": "Austin skyline camera",
            "location": {"city": "Austin", "region": "Texas", "country": "United States", "latitude": 30.2672, "longitude": -97.7431},
            "urls": {"detail": "https://www.windy.com/webcams/12345", "player": "https://player.example.test/cam"},
            "player": {"live": True}
        }]}
        with patch.dict("camera_intelligence.os.environ", {"WINDY_WEBCAMS_API_KEY": "test-key"}):
            with patch.object(camera_intelligence, "_read_json_url", side_effect=[geocode, webcams]) as fetch:
                result = camera_intelligence._windy_public_webcams("Austin")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["result_count"], 1)
        self.assertEqual(result["cameras"][0]["camera_page_url"], "https://www.windy.com/webcams/12345")
        self.assertEqual(result["cameras"][0]["live_status"], "provider marks live")
        self.assertEqual(fetch.call_count, 2)

    def test_public_directory_only_lists_opt_in_sources(self):
        result = public_webcam_directory("Lagos")
        self.assertEqual(result["location_search"], "Lagos")
        self.assertGreaterEqual(len(result["directories"]), 3)
        self.assertIn("does not crawl public IP ranges", result["privacy_boundary"])


if __name__ == "__main__":
    unittest.main()
