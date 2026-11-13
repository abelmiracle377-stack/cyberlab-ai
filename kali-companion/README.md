# CyberLab AI Kali Companion

A command-line research companion for Kali Linux and other Linux distributions. It adds passive OSINT, public vulnerability intelligence, and an optional authenticated loopback bridge that lets the hosted CyberLab dashboard request explicitly authorised local Nmap checks. Python 3.9+; Python standard library only; no pip packages or API keys. Optional `figlet` and `chafa` packages provide the large coloured startup lettering and terminal mascot artwork.

## Install

```bash
git clone https://github.com/abelmiracle377-stack/cyberlab-ai.git
cd cyberlab-ai
sudo apt update && sudo apt install -y figlet chafa nmap
python3 kali-companion/cyberlab.py doctor
python3 kali-companion/cyberlab.py --help
```

## Commands

| Command | Input | What it does |
|---|---|---|
| `domain example.com` | Public domain | RDAP registration data, certificate-transparency names and DNS records |
| `dns example.com` | Public domain | A, AAAA, MX, NS and TXT lookups using public DNS-over-HTTPS |
| `ip 8.8.8.8` | Public global IP | RDAP network registration context |
| `cve "OpenSSH"` | Product/vendor/version/CVE keyword | Searches NIST NVD and returns CVE descriptions and available CVSS severity |
| `triage ./file.exe` | Local file, max 10 MB | SHA-256, file signature, entropy and selected printable-string indicators |
| `port-scan example.com --ports 1-100` | One authorised IP or domain | Nmap TCP scan of up to 100 selected ports; reports open, closed and filtered states |
| `nmap-xml ./scan.xml` | Existing Nmap XML, max 2 MB | Parses host, port and service evidence from an existing report |

## Examples

```bash
# Passive domain research
python3 kali-companion/cyberlab.py domain example.com

# Save the domain report as JSON
python3 kali-companion/cyberlab.py domain example.com --output example-domain.json

# DNS records
python3 kali-companion/cyberlab.py dns example.com

# Public IP registration context
python3 kali-companion/cyberlab.py ip 8.8.8.8

# Scan the first 100 TCP ports on an authorised host/domain
python3 kali-companion/cyberlab.py port-scan example.com --ports 1-100

# Check a selected list on an authorised IP
python3 kali-companion/cyberlab.py port-scan 192.0.2.10 --ports 22,80,443,8080

# Search NIST's vulnerability database
python3 kali-companion/cyberlab.py cve "OpenSSH" --limit 10

# Static file triage
python3 kali-companion/cyberlab.py triage ./sample.bin

# Parse a previously generated Nmap XML report
python3 kali-companion/cyberlab.py nmap-xml ./authorised-scan.xml
```

## Data sources and network behaviour

- Domain registration: RDAP via rdap.org.
- Certificate transparency: crt.sh public search.
- DNS: Cloudflare public DNS-over-HTTPS.
- IP registration: RDAP via rdap.org.
- Vulnerabilities: NIST National Vulnerability Database API.
- File triage and Nmap XML parsing run locally.

The domain/IP/DNS/CVE commands make read-only requests to the named public data providers. The separate `port-scan` command performs a bounded Nmap TCP connect scan against one explicitly authorised IP address or domain, for up to 100 selected ports. It uses light service-version detection and reports `open`, `closed` or `filtered` when determinable; filtered is not the same as closed. It does not scan networks/CIDR ranges. The companion does not perform subdomain brute forcing, exploit attempts, credential attacks, stealth, persistence, shell execution, sample execution or private-person identification. Use active assessment only with explicit authorisation; the XML parser only reads a report you already have.

## Interpretation

RDAP identifies the organisation/network associated with an address range, not a specific person's identity or exact location. Certificate-transparency names may be historical or wildcard entries and need validation. CVE matches are search results, not proof that a particular host is vulnerable. Static indicators are not a malware verdict.

## Limits

HTTP timeout defaults to 12 seconds and can be changed with `--timeout 20`. JSON output can be saved with `-o report.json` or `--output report.json`. Public data providers can rate-limit or be temporarily unavailable. No API keys are required.


## Hosted dashboard ↔ local Kali bridge

The optional bridge pairs the CyberLab website with Nmap running on your Kali machine. It binds only to `127.0.0.1` and does not open an inbound internet port or require a VPS/tunnel.

1. Install Nmap: `sudo apt update && sudo apt install -y nmap`.
2. Start the bridge from the repository root: `python3 kali-companion/bridge.py`.
3. Copy the pairing token printed in the terminal into CyberLab → Kali Connection → Connect to Kali.
4. Keep the terminal open while using the dashboard. Press `Ctrl+C` in that terminal to stop the bridge.

The token is generated locally and stored at `~/.config/cyberlab/bridge-token` with owner-only file permissions (0600). Do not share it. The bridge accepts browser requests only from `https://cyberlab-ai.vercel.app`, requires the token, and listens on loopback only. The website holds the pasted token in page memory and does not persist it.

The dashboard can request a single-target TCP connect scan with light service-version detection on up to 100 selected TCP ports (custom comma-separated lists or ranges such as `22,80,443` or `1-100`). Results distinguish open, closed and filtered ports when determinable; filtered means no definitive response was possible. The bridge uses fixed Nmap arguments; it does not accept arbitrary command-line options, NSE scripts, exploit checks, credentials, stealth/evasion flags, or shell commands. Each run requires an exact target confirmation, an authorisation reference and an explicit ownership/permission confirmation. Loopback, link-local, multicast and reserved targets are blocked. Private LAN targets may be assessed only when they are in your authorised scope.

Browser access to localhost can depend on browser private-network access policies. If the browser blocks the request, check its site permissions and keep the official CyberLab origin unchanged. The bridge is optional; existing CLI commands continue to work without it.
