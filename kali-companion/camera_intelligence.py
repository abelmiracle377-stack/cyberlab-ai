"""Camera discovery and viewing for explicitly authorised camera systems.

LAN discovery is limited to an operator-supplied RFC1918 IPv4 subnet (/24 max).
Manual viewing requires an explicit authorisation confirmation and a single
operator-supplied host. Empty credentials are supported for owner-configured
passwordless cameras. This module never searches public IP ranges or harvests
publicly exposed private camera feeds.
"""
from __future__ import annotations

import concurrent.futures
import getpass
import ipaddress
import re
import shutil
import socket
import subprocess
import urllib.parse

CAMERA_PORTS = (80, 443, 554, 8000, 8080, 8554, 8899)
PUBLIC_WEBCAM_DIRECTORIES = (
    {"name": "EarthCam", "url": "https://www.earthcam.com/", "description": "Publicly published city, landmark and event webcams."},
    {"name": "SkylineWebcams", "url": "https://www.skylinewebcams.com/", "description": "Publicly published scenic and city webcams."},
    {"name": "Explore.org Livecams", "url": "https://explore.org/livecams", "description": "Public wildlife, nature and conservation livestreams."},
    {"name": "Windy Webcams", "url": "https://www.windy.com/webcams", "description": "Public weather and location webcam directory."},
)

def validate_camera_host(value: str) -> str:
    """Accept one explicit IP address or DNS hostname; reject URL/userinfo/path."""
    host = value.strip().strip("[]")
    if not host or len(host) > 253 or any(ch in host for ch in "/@?#"):
        raise ValueError("Enter one camera IP address or hostname only, without a URL, path or credentials.")
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        candidate = host.rstrip(".").encode("idna").decode("ascii").lower()
        if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*", candidate):
            raise ValueError("Camera hostname is not valid.")
        return candidate

def validate_lan_network(value: str) -> ipaddress.IPv4Network:
    """Permit only an explicitly supplied RFC1918 IPv4 subnet of at most 256 addresses."""
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ValueError("Enter a valid private IPv4 subnet, e.g. 192.168.1.0/24.") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("LAN discovery currently supports private IPv4 networks only.")
    rfc1918 = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"), ipaddress.ip_network("192.168.0.0/16"))
    if not any(network.subnet_of(block) for block in rfc1918):
        raise ValueError("Discovery is restricted to RFC1918 private networks you administer.")
    if network.num_addresses > 256:
        raise ValueError("Choose a subnet containing no more than 256 addresses (normally /24 or smaller).")
    return network

def discover_lan_cameras(cidr: str, timeout: float = 0.35, max_workers: int = 64) -> dict:
    """Check common camera ports on an operator-selected private subnet."""
    network = validate_lan_network(cidr)
    if not 0.1 <= float(timeout) <= 2.0:
        raise ValueError("Connection timeout must be between 0.1 and 2 seconds.")
    hosts = list(network.hosts())
    checks = [(str(host), port) for host in hosts for port in CAMERA_PORTS]
    found = {}
    def probe(item):
        host, port = item
        try:
            with socket.create_connection((host, port), timeout=float(timeout)):
                return host, port
        except OSError:
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(int(max_workers), 64))) as pool:
        for result in pool.map(probe, checks):
            if result:
                host, port = result
                found.setdefault(host, []).append(port)
    devices = [
        {"ip": host, "open_camera_related_ports": sorted(ports),
         "possible_services": [
             name for port, name in ((554, "RTSP"), (8554, "RTSP alternate"),
                                     (8000, "vendor service / possible Hikvision"),
                                     (8899, "possible ONVIF/vendor service"),
                                     (80, "HTTP management"), (443, "HTTPS management"),
                                     (8080, "alternate HTTP management"))
             if port in ports
         ]}
        for host, ports in sorted(found.items(), key=lambda item: tuple(int(x) for x in item[0].split(".")))
    ]
    return {"feature": "authorised_private_lan_camera_discovery", "network": str(network),
            "hosts_checked": len(hosts), "ports_checked_per_host": list(CAMERA_PORTS),
            "devices_with_matching_open_ports": devices,
            "camera_identification": "Port matches are clues only; they do not prove that a device is a camera or that a video stream is available.",
            "scope": "Only the explicitly supplied RFC1918 private subnet was checked. No public IP ranges, internet-wide search or video streams were accessed."}

def build_rtsp_url(host: str, port: int, path: str, username: str = "", password: str = "") -> str:
    """Build one RTSP URL; blank username and password means no authentication."""
    target = validate_camera_host(host)
    try:
        selected_port = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError("RTSP port must be an integer between 1 and 65535.") from exc
    if not 1 <= selected_port <= 65535:
        raise ValueError("RTSP port must be between 1 and 65535.")
    stream_path = path.strip()
    if not stream_path.startswith("/") or len(stream_path) > 512 or any(ord(ch) < 32 for ch in stream_path):
        raise ValueError("Enter the camera's RTSP path beginning with / (maximum 512 characters).")
    if (username and not password) or (password and not username):
        raise ValueError("Enter both username and password, or leave both blank for a camera configured without authentication.")
    auth = urllib.parse.quote(username, safe="") + ":" + urllib.parse.quote(password, safe="") + "@" if username else ""
    try:
        address = ipaddress.ip_address(target)
        display_host = "[" + target + "]" if address.version == 6 else target
    except ValueError:
        display_host = target
    safe_path = urllib.parse.quote(stream_path, safe="/%:@!$&'()*+,;=-._~")
    return f"rtsp://{auth}{display_host}:{selected_port}{safe_path}"

def launch_camera_viewer(rtsp_url: str) -> dict:
    """Launch ffplay for the single explicitly configured camera stream."""
    ffplay = shutil.which("ffplay")
    if not ffplay:
        raise ValueError("ffplay is not installed. On Kali, install it with: sudo apt update && sudo apt install ffmpeg")
    parsed = urllib.parse.urlsplit(rtsp_url)
    if parsed.scheme != "rtsp" or not parsed.hostname or not parsed.path:
        raise ValueError("Only a complete RTSP stream URL is accepted.")
    process = subprocess.Popen([ffplay, "-rtsp_transport", "tcp", "-loglevel", "warning", "-i", rtsp_url],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, close_fds=True)
    return {"feature": "authorised_camera_live_viewer", "camera_host": parsed.hostname,
            "rtsp_port": parsed.port or 554, "stream_path": parsed.path, "viewer": "ffplay",
            "viewer_pid": process.pid,
            "authentication_mode": "configured username/password" if parsed.username is not None else "no authentication (owner-configured)",
            "credentials_saved_or_logged": False,
            "note": "The viewer was launched for the one manually entered camera stream. The RTSP URL and credentials are not included in this report."}

def public_webcam_directory(location: str = "") -> dict:
    """Return opt-in public webcam directories; does not enumerate exposed private feeds."""
    return {"feature": "global_public_webcam_directory", "location_search": location.strip()[:120] or "not specified",
            "directories": list(PUBLIC_WEBCAM_DIRECTORIES),
            "how_to_use": "Open a directory and search for the requested city or country. These services publish webcams for public viewing.",
            "privacy_boundary": "CyberLab does not crawl public IP ranges, enumerate exposed CCTV devices, or open feeds merely because authentication is absent."}

def camera_intelligence_menu() -> dict:
    print("\nGLOBAL CAMERA INTELLIGENCE")
    print("  [1] Discover camera-related services on YOUR private Wi-Fi/LAN")
    print("  [2] Connect to and view ONE camera you own or are authorised to access")
    print("  [3] Global public webcam directories (location-based search)")
    print("  [0] Back")
    choice = input("camera-intelligence> ").strip()
    if choice == "0":
        return {}
    if choice == "1":
        print("\nDiscovery is limited to one RFC1918 private subnet (256 addresses maximum).")
        network = input("Your private LAN subnet (e.g. 192.168.1.0/24): ").strip()
        confirmation = input("Type YES to confirm you own/administer this network and authorise these checks: ").strip()
        if confirmation != "YES":
            raise ValueError("LAN discovery cancelled; explicit authorisation confirmation is required.")
        return discover_lan_cameras(network)
    if choice == "2":
        print("\nEnter one camera you own or have explicit permission to access.")
        host = validate_camera_host(input("Camera IP address or hostname: "))
        confirmation = input("Type YES to confirm you own/administer this camera or have permission to view it: ").strip()
        if confirmation != "YES":
            raise ValueError("Camera connection cancelled; explicit authorisation confirmation is required.")
        port_text = input("RTSP port [554]: ").strip() or "554"
        path = input("RTSP stream path [/]: ").strip() or "/"
        username = input("Camera username (leave blank if no username is configured): ").strip()
        password = getpass.getpass("Camera password (leave blank if no password is configured): ") if username else ""
        stream_url = build_rtsp_url(host, int(port_text), path, username, password)
        result = launch_camera_viewer(stream_url)
        stream_url = None
        return result
    if choice == "3":
        location = input("Country or city to search (e.g. Nigeria or Lagos): ").strip()
        result = public_webcam_directory(location)
        print("\nPublicly published webcam directories:")
        for item in result["directories"]:
            print(f"  {item['name']}: {item['url']}\n    {item['description']}")
        print("\nSearch the selected location inside these public webcam directories.")
        return result
    raise ValueError("Choose one of the listed camera options.")
