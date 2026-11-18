# CyberLab AI — Native Network Intelligence

## Current implementation slice

CyberLab now has a first native, Burp-independent passive packet-capture backend in the Kali companion.

- `GET /network/interfaces` lists local interface names and operational state only. It does not expose interface MAC or IP addresses.
- `POST /network/capture` performs a short, bounded capture on one selected interface.
- Captures use the locally installed `tcpdump` executable; no package installation is performed by CyberLab.
- Supported fixed capture filters are `ssh`, `dns`, `tcp`, `udp` and `icmp`. Caller-supplied BPF expressions are rejected.
- The default filter is SSH (`tcp port 22`). Capture duration is limited to 30 seconds, packet count to 2,000 and snap length to 96 bytes.
- A capture requires the paired bridge token, explicit authorisation confirmation, an exact retyped interface name and an authorisation/lab reference.
- Only one capture can run at a time through the bridge.
- PCAP files are retained locally under `~/.local/share/cyberlab/captures/` with owner-only file permissions. Each result includes a SHA-256 evidence hash.
- CyberLab returns packet counts, protocol counts and bounded endpoint metadata only. It does not forward packet payloads to the dashboard or AI.

## SSH visibility and encryption

The SSH filter captures packets for TCP port 22. CyberLab can count packets and inspect network-level metadata such as endpoints and packet timing. The initial SSH handshake may expose protocol negotiation banners, but the encrypted SSH session does not reveal passwords, commands or terminal contents from packet capture alone. Decryption would require separately obtained session secrets or endpoint-side telemetry; this module does not attempt decryption.

## Local setup

Install tcpdump on the paired Kali workstation if it is not already installed:

```bash
sudo apt update
sudo apt install -y tcpdump
```

The user running the companion must have the operating-system permissions/capabilities needed to capture on the selected interface. CyberLab does not invoke `sudo`, change capabilities, or modify VM operating-system settings automatically. If capture permissions are unavailable, the endpoint returns a capture failure rather than escalating privileges.

## Request shape

```json
{
  "interface": "eth0",
  "confirmationInterface": "eth0",
  "authorizationConfirmed": true,
  "authorizationReference": "LAB-ENGAGEMENT-001",
  "durationSeconds": 10,
  "packetLimit": 500,
  "filter": "ssh"
}
```

Use only on a network/interface that you own or are explicitly authorised to monitor. The authorisation reference is an audit label, not independent proof of permission.

## Not implemented in this slice

The initial browser workspace is available at `/network-intelligence`; it discovers local interfaces and starts a single bounded capture after explicit authorisation. Capture is synchronous and runs for the selected duration (maximum 30 seconds).


- PCAP/PCAPNG upload and offline analysis.
- Deep protocol dissection with TShark/Wireshark.
- DNS conversation timelines, TCP stream reconstruction and TLS metadata enrichment.
- AI anomaly detection, alert correlation and case/evidence integration.
- Wireless monitor mode, packet injection, deauthentication or man-in-the-middle features.

This implementation is passive capture only. It does not initiate connections, scan targets, inject packets, intercept traffic, decrypt sessions or alter the CyberLab VM OS/VPS build.
