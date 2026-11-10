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
import json
import os
import re
import shutil
import socket
import subprocess
import urllib.parse
import urllib.request
import urllib.error

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

def detect_private_lan_networks() -> list[str]:
    """Discover RFC1918 interface networks configured on this Kali host."""
    ip_cmd = shutil.which("ip")
    if not ip_cmd:
        return []
    try:
        result = subprocess.run(
            [ip_cmd, "-o", "-f", "inet", "addr", "show", "scope", "global"],
            capture_output=True, text=True, timeout=3, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return []
    networks = set()
    for line in result.stdout.splitlines():
        match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
        if not match:
            continue
        try:
            interface_network = ipaddress.ip_interface(match.group(1)).network
            rfc1918 = (ipaddress.ip_network("10.0.0.0/8"),
                       ipaddress.ip_network("172.16.0.0/12"),
                       ipaddress.ip_network("192.168.0.0/16"))
            if any(interface_network.network_address in block for block in rfc1918):
                # Never widen a configured interface prefix; cap discovery to /24.
                if interface_network.num_addresses > 256:
                    interface_address = ipaddress.ip_interface(match.group(1)).ip
                    interface_network = ipaddress.ip_network(
                        (interface_address, 24), strict=False
                    )
                if interface_network.num_addresses <= 256:
                    networks.add(str(interface_network))
        except ValueError:
            continue
    return sorted(networks)


def detect_private_lan_interfaces() -> list[dict]:
    """Return IPv4 and IPv6 addresses/prefixes configured on this Kali host."""
    ip_cmd = shutil.which("ip")
    if not ip_cmd:
        return []
    interfaces = []
    for family in ("inet", "inet6"):
        try:
            result = subprocess.run(
                [ip_cmd, "-o", "-f", family, "addr", "show"],
                capture_output=True, text=True, timeout=3, check=False
            )
        except (OSError, subprocess.SubprocessError):
            continue
        for line in result.stdout.splitlines():
            match = re.search(r"^(\d+):\s+([^\s@]+).*?\binet6?\s+([0-9a-fA-F:.]+/\d+)", line)
            if not match:
                continue
            try:
                interface = ipaddress.ip_interface(match.group(3))
                if family == "inet":
                    if not isinstance(interface, ipaddress.IPv4Interface) or not interface.ip.is_private:
                        continue
                    network = interface.network
                    if network.num_addresses > 256:
                        network = ipaddress.ip_network((interface.ip, 24), strict=False)
                    if not any(network.subnet_of(block) for block in (
                        ipaddress.ip_network("10.0.0.0/8"),
                        ipaddress.ip_network("172.16.0.0/12"),
                        ipaddress.ip_network("192.168.0.0/16"),
                    )):
                        continue
                    interfaces.append({"interface": match.group(2), "family": "IPv4",
                                       "ip": str(interface.ip), "ipv4": str(interface.ip), "network": str(network)})
                else:
                    if not isinstance(interface, ipaddress.IPv6Interface):
                        continue
                    if interface.ip.is_unspecified or interface.ip.is_loopback:
                        continue
                    interfaces.append({"interface": match.group(2), "family": "IPv6",
                                       "ip": str(interface.ip), "ipv6": str(interface.ip), "network": str(interface.network),
                                       "scope": "link" if interface.ip.is_link_local else "global"})
            except ValueError:
                continue
    return interfaces

def validate_camera_on_detected_lan(host: str, interfaces: list[dict] | None = None) -> dict:
    """Require the camera IP to fall within a prefix configured on this Kali host."""
    target = validate_camera_host(host)
    try:
        address_text = target.split("%", 1)[0]
        address = ipaddress.ip_address(address_text)
    except ValueError as exc:
        raise ValueError("Enter a valid private IPv4 or IPv6 camera address; hostnames cannot be subnet-matched.") from exc
    detected = interfaces if interfaces is not None else detect_private_lan_interfaces()
    matching = []
    normalized_interfaces = []
    for item in detected:
        try:
            if isinstance(item, str):
                network = ipaddress.ip_network(item, strict=False)
                normalized = {"interface": "detected-network", "family": "IPv{}".format(network.version),
                              "ip": str(network.network_address), "network": str(network)}
            else:
                normalized = item
                network = ipaddress.ip_network(normalized["network"], strict=False)
                local_address = ipaddress.ip_address(normalized.get("ip", str(network.network_address)))
                if address.version != local_address.version:
                    continue
            normalized_interfaces.append(normalized)
            if address.version == network.version and address in network:
                if address.version == 6 and address.is_link_local and normalized.get("interface") not in target:
                    continue
                matching.append(normalized)
        except (KeyError, ValueError):
            continue
    detected = normalized_interfaces
    if not matching:
        if not detected:
            raise ValueError("Kali has no detected local IPv4/IPv6 interface address. Connect to the same Wi-Fi/LAN as the camera and retry.")
        local_summary = ", ".join("{} {} {} ({})".format(item.get("interface"), item.get("family"), item.get("ip"), item.get("network")) for item in detected)
        raise ValueError("Camera IP {} is not inside Kali's detected local interface address/subnet: {}. Connect both devices to the same network or verify the camera IP.".format(target, local_summary))
    selected = matching[0]
    connection_host = target
    if address.version == 6 and address.is_link_local and "%" not in target:
        connection_host = target + "%" + selected["interface"]
    return {
        "camera_ip": target,
        "kali_ip": selected["ip"],
        "interface": selected["interface"],
        "ip_version": address.version,
        "matching_local_network": selected["network"],
        "connection_host": connection_host,
        "detected_local_interfaces": detected,
        "message": "Your Kali IP address is {}. It corresponds to the camera IP you entered ({}); both are on {}. Proceeding to stream.".format(selected["ip"], target, selected["network"]),
    }


def validate_camera_port(value: str | int) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Camera RTSP port must be a number between 1 and 65535.") from exc
    if not 1 <= port <= 65535:
        raise ValueError("Camera RTSP port must be between 1 and 65535.")
    return port


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
                                     (8899, "possible vendor service"),
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
        display_host = "[" + target.replace("%", "%25") + "]" if address.version == 6 else target
    except ValueError:
        display_host = target
    safe_path = urllib.parse.quote(stream_path, safe="/%:@!def validate_camera_on_detected_lan(host: str, networks: list[str] | None = None) -> dict:'()*+,;=-._~")
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
            "credentials_saved_in_reports": False,
            "process_argument_visibility": "The RTSP URL is passed to ffplay; local users with process-inspection privileges may be able to see it.",
            "note": "The viewer was launched for the one manually entered camera stream. The RTSP URL and credentials are not included in this report."}

def _read_json_url(url: str, headers: dict | None = None, timeout: float = 8.0) -> dict:
    request = urllib.request.Request(url, headers=headers or {"User-Agent": "CyberLab-Camera-Directory/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read(2_000_000).decode("utf-8", errors="replace"))


def _windy_public_webcams(location: str, timeout: float = 8.0) -> dict:
    """Query Windy's licensed, operator-published webcam catalogue when configured."""
    api_key = os.environ.get("WINDY_WEBCAMS_API_KEY", "").strip()
    if not api_key:
        return {"status": "not_configured", "message": "Set WINDY_WEBCAMS_API_KEY to enable structured camera results from Windy's official public webcam catalogue."}
    geo_url = "https://geocoding-api.open-meteo.com/v1/search?" + urllib.parse.urlencode(
        {"name": location, "count": 1, "language": "en", "format": "json"}
    )
    try:
        geodata = _read_json_url(geo_url, timeout=timeout)
        places = geodata.get("results") or []
        if not places:
            return {"status": "no_location_match", "message": "The location could not be resolved."}
        place = places[0]
        lat, lon = float(place["latitude"]), float(place["longitude"])
        params = urllib.parse.urlencode({
            "nearby": f"{lat},{lon},100", "limit": 50,
            "include": "categories,images,location,player,urls", "lang": "en",
        })
        api_url = "https://api.windy.com/webcams/api/v3/webcams?" + params
        payload = _read_json_url(api_url, headers={"x-windy-api-key": api_key, "User-Agent": "CyberLab-Camera-Directory/1.0"}, timeout=timeout)
        cameras = []
        for cam in payload.get("webcams", []):
            loc, urls, player = cam.get("location") or {}, cam.get("urls") or {}, cam.get("player") or {}
            detail_url = urls.get("detail") or urls.get("website") or urls.get("web")
            webcam_id = cam.get("id") or cam.get("webcamId")
            if not detail_url and webcam_id:
                detail_url = "https://www.windy.com/webcams/" + urllib.parse.quote(str(webcam_id), safe="")
            if not detail_url:
                continue
            cameras.append({
                "name": str(cam.get("title") or cam.get("name") or "Public webcam")[:180],
                "location": ", ".join(str(x) for x in (loc.get("city"), loc.get("region"), loc.get("country")) if x),
                "latitude": loc.get("latitude"), "longitude": loc.get("longitude"),
                "camera_page_url": detail_url,
                "viewer_url": urls.get("player") or player.get("url"),
                "live_status": "provider marks live" if player.get("live") else "not confirmed live",
                "source": "Windy official public webcam catalogue",
            })
        return {
            "status": "ok",
            "resolved_location": {"name": place.get("name"), "admin1": place.get("admin1"), "country": place.get("country"), "latitude": lat, "longitude": lon},
            "search_radius_km": 100, "result_count": len(cameras), "cameras": cameras,
            "note": "A directory listing does not guarantee continuous live video."
        }
    except (OSError, ValueError, KeyError, TypeError, urllib.error.URLError, json.JSONDecodeError) as exc:
        return {"status": "unavailable", "message": f"Windy catalogue lookup failed: {str(exc)[:240]}"}


def public_webcam_directory(location: str = "", timeout: float = 8.0) -> dict:
    """Search operator-published webcams by location; never probe arbitrary CCTV hosts."""
    query = location.strip()[:120]
    if not query:
        raise ValueError("Enter a city, state, country or landmark to search for public webcams.")
    targeted = [
        {"name": "EarthCam", "search_url": "https://www.google.com/search?" + urllib.parse.urlencode({"q": f"site:earthcam.com {query} webcam"}), "directory_url": "https://www.earthcam.com/search/advanced-search.php", "description": f"Search EarthCam listings for {query}."},
        {"name": "SkylineWebcams", "search_url": "https://www.google.com/search?" + urllib.parse.urlencode({"q": f"site:skylinewebcams.com {query} webcam"}), "directory_url": "https://www.skylinewebcams.com/", "description": f"Search published scenic webcams near {query}."},
        {"name": "Explore.org Livecams", "search_url": "https://www.google.com/search?" + urllib.parse.urlencode({"q": f"site:explore.org/livecams {query}"}), "directory_url": "https://explore.org/livecams", "description": f"Search Explore.org cameras for {query}."},
        {"name": "Windy Webcams", "search_url": "https://www.windy.com/webcams/" + urllib.parse.quote_plus(query), "directory_url": "https://www.windy.com/webcams", "description": f"Open Windy's webcam map for {query}."},
    ]
    return {
        "feature": "location_specific_public_webcam_search",
        "location_search": query,
        "targeted_searches": targeted,
        "directories": list(PUBLIC_WEBCAM_DIRECTORIES),
        "structured_catalogue_search": _windy_public_webcams(query, timeout=timeout),
        "how_to_use": "Open targeted search links for matching published camera pages. Set WINDY_WEBCAMS_API_KEY to return structured Windy camera records and individual camera-page URLs.",
        "privacy_boundary": "CyberLab does not crawl public IP ranges; it does not enumerate arbitrary exposed CCTV. Only operator-published public webcam directories are searched; authentication is never bypassed and private feeds are not opened.",
    }

def camera_intelligence_menu() -> dict:
    print("\nGLOBAL CAMERA INTELLIGENCE")
    print("  [1] Discover camera-related services on YOUR private Wi-Fi/LAN")
    print("  [2] Connect to and view ONE camera you own or are authorised to access")
    print("  [3] Global public webcam directories (location-based search)")
    print("  [4] Camera exposure assessment & responsible disclosure (owner-authorised)")
    print("  [0] Back")
    choice = input("camera-intelligence> ").strip()
    if choice == "0":
        return {}
    if choice == "1":
        print("\nDiscovery is limited to one RFC1918 private subnet (256 addresses maximum).")
        network = input("Your private LAN subnet (e.g. 192.168.1.0/24; press Enter to detect it): ").strip()
        if network:
            try:
                selected_network = validate_lan_network(network)
            except ValueError as exc:
                detected = detect_private_lan_networks()
                if not detected:
                    print(f"\\nThe supplied value is not an RFC1918 private subnet: {exc}")
                    print("No private LAN subnet could be detected automatically.")
                    print("For public webcams, choose menu option 3 and search by city or country.")
                    return {
                        "feature": "camera_discovery_input_diagnostic",
                        "status": "private_lan_not_found",
                        "supplied_value": network,
                        "reason": str(exc),
                        "public_ip_scanning": "Not performed. Public IP ranges are not scanned for exposed cameras.",
                        "next_step": "Enter your router's private LAN subnet (for example 192.168.1.0/24), or use option 3 for public webcam directories."
                    }
                print("\\nThat is not a private LAN subnet. Detected private network(s) on this Kali host:")
                for item in detected:
                    print("  " + item)
                if len(detected) == 1:
                    network = detected[0]
                    print("Using the detected local network: " + network)
                else:
                    network = input("Enter one of the detected private subnets: ").strip()
                    if network not in detected:
                        raise ValueError("Choose one of the detected private subnets.")
        else:
            detected = detect_private_lan_networks()
            if not detected:
                raise ValueError("No private LAN subnet was detected. Connect to your own Wi-Fi/LAN or use option 3 for public webcam directories.")
            print("\\nDetected private network(s) on this Kali host:")
            for item in detected:
                print("  " + item)
            network = detected[0] if len(detected) == 1 else input("Choose a detected private subnet: ").strip()
            if network not in detected:
                raise ValueError("Choose one of the detected private subnets.")
        confirmation = input("Type YES to confirm you own/administer this network and authorise these checks: ").strip()
        if confirmation != "YES":
            raise ValueError("LAN discovery cancelled; explicit authorisation confirmation is required.")
        return discover_lan_cameras(network)
    if choice == "2":
        print("\nEnter one camera you own or have explicit permission to access.")
        host = validate_camera_host(input("Camera/device IPv4 or IPv6 address: "))
        confirmation = input("Type YES to confirm you own/administer this camera or have permission to view it: ").strip()
        if confirmation.upper() != "YES":
            raise ValueError("Camera connection cancelled; explicit authorisation confirmation is required.")

        local_interfaces = detect_private_lan_interfaces()
        detected_networks = sorted({item["network"] for item in local_interfaces})
        if local_interfaces:
            print("\nKali's detected local Wi-Fi/LAN IPv4 details:")
            for item in local_interfaces:
                print("  {}: {} ({})".format(item["interface"], item["ipv4"], item["network"]))
        else:
            raise ValueError("Kali could not detect a private Wi-Fi/LAN IPv4 address. Connect to the same Wi-Fi/router as the camera and retry.")

        network_match = validate_camera_on_detected_lan(host, detected_networks)
        print("Camera IP matches Kali's local network: " + network_match["matching_local_network"])

        port_text = input("Camera RTSP port [554]: ").strip() or "554"
        port = validate_camera_port(port_text)
        print("Checking the selected RTSP port on the one authorised camera...")
        try:
            with socket.create_connection((connection_host, port), timeout=2.0):
                print("RTSP port {} is reachable.".format(port))
        except OSError as exc:
            raise ValueError(
                "Could not connect to {}:{} ({}). Check the camera RTSP setting, port, power and firewall. "
                "The device may use a different RTSP port or have RTSP disabled."
                .format(host, port, exc)
            ) from exc

        path = input("RTSP stream path [/]: ").strip() or "/"
        username = input("Camera username (leave blank if no username is configured): ").strip()
        password = getpass.getpass("Camera password (leave blank if no username is configured): ") if username else ""
        stream_url = build_rtsp_url(connection_host, port, path, username, password)
        result = launch_camera_viewer(stream_url)
        stream_url = None
        result["network_check"] = network_match
        result["port_check"] = {"port": port, "status": "reachable"}
        return result
    if choice == "4":
        from camera_exposure_defence import run_camera_exposure_assessment
        return run_camera_exposure_assessment()
    if choice == "3":
        location = input("Country, state, city or landmark to search: ").strip()
        result = public_webcam_directory(location)
        print("\\nLocation-specific public webcam searches:")
        for item in result["targeted_searches"]:
            print(f"  {item['name']}: {item['search_url']}\\n    {item['description']}")
        catalogue = result["structured_catalogue_search"]
        print(f"\\nWindy catalogue lookup: {catalogue.get('status')}")
        for camera in catalogue.get("cameras", []):
            print(f"  {camera['name']} — {camera['location'] or 'location not supplied'}")
            print(f"    Camera page: {camera['camera_page_url']}")
            if camera.get("viewer_url"):
                print(f"    Viewer: {camera['viewer_url']}")
        if not catalogue.get("cameras"):
            print("  No structured camera records returned. Use the targeted search links above.")
            if catalogue.get("message"):
                print("  " + catalogue["message"])
        return result
    raise ValueError("Choose one of the listed camera options.")

    """Require one private camera IPv4 address to belong to a subnet configured on Kali."""
    target = validate_camera_host(host)
    try:
        address = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ValueError("Enter the camera's private IPv4 address so it can be matched to Kali's local network.") from exc
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_private:
        raise ValueError("Camera IP must be a private IPv4 address on your local Wi-Fi/LAN.")
    detected = networks if networks is not None else detect_private_lan_networks()
    parsed_networks = [validate_lan_network(item) for item in detected]
    matching = [str(network) for network in parsed_networks if address in network]
    if not matching:
        if not parsed_networks:
            raise ValueError("Kali has no detected private Wi-Fi/LAN IPv4 subnet. Connect to the same Wi-Fi/LAN as the camera and try again.")
        raise ValueError(
            "Camera IP {} is not inside Kali's detected local network(s): {}. "
            "Check that both devices are connected to the same Wi-Fi/router and that the camera IP is correct."
            .format(address, ", ".join(str(network) for network in parsed_networks))
        )
    return {"camera_ip": str(address), "matching_local_network": matching[0],
            "detected_local_networks": [str(network) for network in parsed_networks]}


def validate_camera_port(value: str | int) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Camera RTSP port must be a number between 1 and 65535.") from exc
    if not 1 <= port <= 65535:
        raise ValueError("Camera RTSP port must be between 1 and 65535.")
    return port


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
                                     (8899, "possible vendor service"),
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
            "credentials_saved_in_reports": False,
            "process_argument_visibility": "The RTSP URL is passed to ffplay; local users with process-inspection privileges may be able to see it.",
            "note": "The viewer was launched for the one manually entered camera stream. The RTSP URL and credentials are not included in this report."}

def _read_json_url(url: str, headers: dict | None = None, timeout: float = 8.0) -> dict:
    request = urllib.request.Request(url, headers=headers or {"User-Agent": "CyberLab-Camera-Directory/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read(2_000_000).decode("utf-8", errors="replace"))


def _windy_public_webcams(location: str, timeout: float = 8.0) -> dict:
    """Query Windy's licensed, operator-published webcam catalogue when configured."""
    api_key = os.environ.get("WINDY_WEBCAMS_API_KEY", "").strip()
    if not api_key:
        return {"status": "not_configured", "message": "Set WINDY_WEBCAMS_API_KEY to enable structured camera results from Windy's official public webcam catalogue."}
    geo_url = "https://geocoding-api.open-meteo.com/v1/search?" + urllib.parse.urlencode(
        {"name": location, "count": 1, "language": "en", "format": "json"}
    )
    try:
        geodata = _read_json_url(geo_url, timeout=timeout)
        places = geodata.get("results") or []
        if not places:
            return {"status": "no_location_match", "message": "The location could not be resolved."}
        place = places[0]
        lat, lon = float(place["latitude"]), float(place["longitude"])
        params = urllib.parse.urlencode({
            "nearby": f"{lat},{lon},100", "limit": 50,
            "include": "categories,images,location,player,urls", "lang": "en",
        })
        api_url = "https://api.windy.com/webcams/api/v3/webcams?" + params
        payload = _read_json_url(api_url, headers={"x-windy-api-key": api_key, "User-Agent": "CyberLab-Camera-Directory/1.0"}, timeout=timeout)
        cameras = []
        for cam in payload.get("webcams", []):
            loc, urls, player = cam.get("location") or {}, cam.get("urls") or {}, cam.get("player") or {}
            detail_url = urls.get("detail") or urls.get("website") or urls.get("web")
            webcam_id = cam.get("id") or cam.get("webcamId")
            if not detail_url and webcam_id:
                detail_url = "https://www.windy.com/webcams/" + urllib.parse.quote(str(webcam_id), safe="")
            if not detail_url:
                continue
            cameras.append({
                "name": str(cam.get("title") or cam.get("name") or "Public webcam")[:180],
                "location": ", ".join(str(x) for x in (loc.get("city"), loc.get("region"), loc.get("country")) if x),
                "latitude": loc.get("latitude"), "longitude": loc.get("longitude"),
                "camera_page_url": detail_url,
                "viewer_url": urls.get("player") or player.get("url"),
                "live_status": "provider marks live" if player.get("live") else "not confirmed live",
                "source": "Windy official public webcam catalogue",
            })
        return {
            "status": "ok",
            "resolved_location": {"name": place.get("name"), "admin1": place.get("admin1"), "country": place.get("country"), "latitude": lat, "longitude": lon},
            "search_radius_km": 100, "result_count": len(cameras), "cameras": cameras,
            "note": "A directory listing does not guarantee continuous live video."
        }
    except (OSError, ValueError, KeyError, TypeError, urllib.error.URLError, json.JSONDecodeError) as exc:
        return {"status": "unavailable", "message": f"Windy catalogue lookup failed: {str(exc)[:240]}"}


def public_webcam_directory(location: str = "", timeout: float = 8.0) -> dict:
    """Search operator-published webcams by location; never probe arbitrary CCTV hosts."""
    query = location.strip()[:120]
    if not query:
        raise ValueError("Enter a city, state, country or landmark to search for public webcams.")
    targeted = [
        {"name": "EarthCam", "search_url": "https://www.google.com/search?" + urllib.parse.urlencode({"q": f"site:earthcam.com {query} webcam"}), "directory_url": "https://www.earthcam.com/search/advanced-search.php", "description": f"Search EarthCam listings for {query}."},
        {"name": "SkylineWebcams", "search_url": "https://www.google.com/search?" + urllib.parse.urlencode({"q": f"site:skylinewebcams.com {query} webcam"}), "directory_url": "https://www.skylinewebcams.com/", "description": f"Search published scenic webcams near {query}."},
        {"name": "Explore.org Livecams", "search_url": "https://www.google.com/search?" + urllib.parse.urlencode({"q": f"site:explore.org/livecams {query}"}), "directory_url": "https://explore.org/livecams", "description": f"Search Explore.org cameras for {query}."},
        {"name": "Windy Webcams", "search_url": "https://www.windy.com/webcams/" + urllib.parse.quote_plus(query), "directory_url": "https://www.windy.com/webcams", "description": f"Open Windy's webcam map for {query}."},
    ]
    return {
        "feature": "location_specific_public_webcam_search",
        "location_search": query,
        "targeted_searches": targeted,
        "directories": list(PUBLIC_WEBCAM_DIRECTORIES),
        "structured_catalogue_search": _windy_public_webcams(query, timeout=timeout),
        "how_to_use": "Open targeted search links for matching published camera pages. Set WINDY_WEBCAMS_API_KEY to return structured Windy camera records and individual camera-page URLs.",
        "privacy_boundary": "CyberLab does not crawl public IP ranges; it does not enumerate arbitrary exposed CCTV. Only operator-published public webcam directories are searched; authentication is never bypassed and private feeds are not opened.",
    }

def camera_intelligence_menu() -> dict:
    print("\nGLOBAL CAMERA INTELLIGENCE")
    print("  [1] Discover camera-related services on YOUR private Wi-Fi/LAN")
    print("  [2] Connect to and view ONE camera you own or are authorised to access")
    print("  [3] Global public webcam directories (location-based search)")
    print("  [4] Camera exposure assessment & responsible disclosure (owner-authorised)")
    print("  [0] Back")
    choice = input("camera-intelligence> ").strip()
    if choice == "0":
        return {}
    if choice == "1":
        print("\nDiscovery is limited to one RFC1918 private subnet (256 addresses maximum).")
        network = input("Your private LAN subnet (e.g. 192.168.1.0/24; press Enter to detect it): ").strip()
        if network:
            try:
                selected_network = validate_lan_network(network)
            except ValueError as exc:
                detected = detect_private_lan_networks()
                if not detected:
                    print(f"\\nThe supplied value is not an RFC1918 private subnet: {exc}")
                    print("No private LAN subnet could be detected automatically.")
                    print("For public webcams, choose menu option 3 and search by city or country.")
                    return {
                        "feature": "camera_discovery_input_diagnostic",
                        "status": "private_lan_not_found",
                        "supplied_value": network,
                        "reason": str(exc),
                        "public_ip_scanning": "Not performed. Public IP ranges are not scanned for exposed cameras.",
                        "next_step": "Enter your router's private LAN subnet (for example 192.168.1.0/24), or use option 3 for public webcam directories."
                    }
                print("\\nThat is not a private LAN subnet. Detected private network(s) on this Kali host:")
                for item in detected:
                    print("  " + item)
                if len(detected) == 1:
                    network = detected[0]
                    print("Using the detected local network: " + network)
                else:
                    network = input("Enter one of the detected private subnets: ").strip()
                    if network not in detected:
                        raise ValueError("Choose one of the detected private subnets.")
        else:
            detected = detect_private_lan_networks()
            if not detected:
                raise ValueError("No private LAN subnet was detected. Connect to your own Wi-Fi/LAN or use option 3 for public webcam directories.")
            print("\\nDetected private network(s) on this Kali host:")
            for item in detected:
                print("  " + item)
            network = detected[0] if len(detected) == 1 else input("Choose a detected private subnet: ").strip()
            if network not in detected:
                raise ValueError("Choose one of the detected private subnets.")
        confirmation = input("Type YES to confirm you own/administer this network and authorise these checks: ").strip()
        if confirmation != "YES":
            raise ValueError("LAN discovery cancelled; explicit authorisation confirmation is required.")
        return discover_lan_cameras(network)
    if choice == "2":
        print("\nEnter one camera you own or have explicit permission to access.")
        host = validate_camera_host(input("Camera/device private IPv4 address: "))
        confirmation = input("Type YES to confirm you own/administer this camera or have permission to view it: ").strip()
        if confirmation.upper() != "YES":
            raise ValueError("Camera connection cancelled; explicit authorisation confirmation is required.")

        local_interfaces = detect_private_lan_interfaces()
        if local_interfaces:
            print("\nKali detected these local network addresses:")
            for item in local_interfaces:
                print("  {} {}: {} ({})".format(item["interface"], item["family"], item["ip"], item["network"]))
        else:
            raise ValueError("Kali could not detect a local IPv4/IPv6 address. Connect to the same Wi-Fi/LAN as the camera and retry.")

        network_match = validate_camera_on_detected_lan(host, local_interfaces)
        print(network_match["message"])
        connection_host = network_match["connection_host"]

        port_text = input("Camera RTSP port [554]: ").strip() or "554"
        port = validate_camera_port(port_text)
        print("Checking the selected RTSP port on the one authorised camera...")
        try:
            with socket.create_connection((host, port), timeout=2.0):
                print("RTSP port {} is reachable.".format(port))
        except OSError as exc:
            raise ValueError(
                "Could not connect to {}:{} ({}). Check the camera RTSP setting, port, power and firewall. "
                "The device may use a different RTSP port or have RTSP disabled."
                .format(host, port, exc)
            ) from exc

        path = input("RTSP stream path [/]: ").strip() or "/"
        username = input("Camera username (leave blank if no username is configured): ").strip()
        password = getpass.getpass("Camera password (leave blank if no username is configured): ") if username else ""
        stream_url = build_rtsp_url(host, port, path, username, password)
        result = launch_camera_viewer(stream_url)
        stream_url = None
        result["network_check"] = network_match
        result["port_check"] = {"port": port, "status": "reachable"}
        return result
    if choice == "4":
        from camera_exposure_defence import run_camera_exposure_assessment
        return run_camera_exposure_assessment()
    if choice == "3":
        location = input("Country, state, city or landmark to search: ").strip()
        result = public_webcam_directory(location)
        print("\\nLocation-specific public webcam searches:")
        for item in result["targeted_searches"]:
            print(f"  {item['name']}: {item['search_url']}\\n    {item['description']}")
        catalogue = result["structured_catalogue_search"]
        print(f"\\nWindy catalogue lookup: {catalogue.get('status')}")
        for camera in catalogue.get("cameras", []):
            print(f"  {camera['name']} — {camera['location'] or 'location not supplied'}")
            print(f"    Camera page: {camera['camera_page_url']}")
            if camera.get("viewer_url"):
                print(f"    Viewer: {camera['viewer_url']}")
        if not catalogue.get("cameras"):
            print("  No structured camera records returned. Use the targeted search links above.")
            if catalogue.get("message"):
                print("  " + catalogue["message"])
        return result
    raise ValueError("Choose one of the listed camera options.")
