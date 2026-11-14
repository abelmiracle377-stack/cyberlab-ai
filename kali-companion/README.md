# CyberLab AI Kali Companion

A command-line research companion for Kali Linux and other Linux distributions. It adds passive OSINT, public vulnerability intelligence, and an optional authenticated loopback bridge that lets the hosted CyberLab dashboard request explicitly authorised local Nmap checks. Python 3.9+; Python standard library only; no pip packages or API keys. Optional `figlet` and `chafa` packages provide the large coloured startup lettering and terminal mascot artwork.

## Install

```bash
git clone https://github.com/abelmiracle377-stack/cyberlab-ai.git
cd cyberlab-ai
sudo apt update && sudo apt install -y figlet chafa nmap gddrescue testdisk foremost ntfs-3g sleuth-kit
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
| `port-scan example.com --ports 1-100` / `nmap example.com --ports 1-100` | One authorised IP or domain | Runs the Nmap TCP scanner for up to 100 selected ports; reports open, closed and filtered states |
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

The optional bridge pairs the CyberLab website with the local Kali/CyberLab AI OS runner. It exposes an authenticated tool inventory, a non-executing natural-language planner, fixed passive research workflows, and a growing set of safety-reviewed local workflows. It binds only to `127.0.0.1` and does not open an inbound internet port or require a VPS/tunnel.

1. Install Nmap: `sudo apt update && sudo apt install -y nmap`.
2. Start the bridge from the repository root: `sudo python3 kali-companion/bridge.py` when you need disk imaging. Running the bridge as root grants it elevated local privileges; keep the token private and stop the bridge when finished.
3. Copy the pairing token printed in the terminal into CyberLab → Kali Connection → Connect to Kali.
4. Keep the terminal open while using the dashboard. Press `Ctrl+C` in that terminal to stop the bridge.

The token is generated locally and stored at `~/.config/cyberlab/bridge-token` with owner-only file permissions (0600). Do not share it. The bridge accepts browser requests only from the production CyberLab origin plus `http://localhost:3000` / `http://127.0.0.1:3000` for self-hosted development, requires the token, and listens on loopback only. To permit a specific Vercel preview or custom self-hosted origin, set `CYBERLAB_ALLOWED_ORIGINS` to a comma-separated list of exact HTTPS origins before starting the bridge (for example, `sudo env CYBERLAB_ALLOWED_ORIGINS=https://your-preview.example python3 kali-companion/bridge.py`). No wildcard origins are accepted. The website holds the pasted token in page memory and does not persist it.

The authenticated `POST /research` endpoint accepts only four fixed actions: `dns` (A/AAAA/MX/NS/TXT), `domain` (RDAP, certificate-transparency names and DNS), `ip` (public global IP RDAP only), and `cve` (NIST NVD keyword search). Requests have strict input validation, fixed eight-second provider timeouts, a 512 KB response cap and no shell execution. These are passive public-source lookups; they do not scan or modify targets. The dashboard presents the results as structured JSON.\n\nThe authenticated `POST /plan` endpoint accepts a bounded natural-language cybersecurity task and returns a deterministic plan, suggested tools and missing scope information. Planning never starts execution. A target in a prompt is not proof of authorisation.\n\nThe authenticated `GET /tools` endpoint inventories the curated Kali tool catalogue (information gathering, vulnerability analysis, web testing, password auditing, wireless, Metasploit, traffic analysis, Active Directory, forensics, reverse engineering and network utilities). It detects installed executables and returns package-specific `apt` install suggestions for missing tools. Inventory is read-only: it does not install packages or execute discovered binaries. The catalogue marks each tool as passive, safe-scan, local-audit, local-analysis, manual-only or blocked for unattended automation. CamPhish is deliberately excluded from automation; online password-guessing tools are not launched unattended. Metasploit is initially limited to safe module metadata and non-destructive checks.

The authenticated `POST /services` endpoint performs bounded, non-authenticating identification on up to eight reviewed TCP ports (21, 22, 25, 80, 110, 143, 443, 445, 587, 993, 995, 8080 and 8443). It requires the same exact target retyping, authorisation checkbox and engagement reference as the Nmap scan. It reads available FTP/SSH/SMTP/POP3/IMAP banners, sends only an HTTP `HEAD /` request, and reads TLS certificate metadata on selected TLS ports. It does not log in, guess credentials, transfer files, send exploit payloads or change server state. Connection attempts have a two-second timeout and the workflow accepts at most eight ports. `closed_or_filtered` is inconclusive. The dashboard displays the returned evidence as JSON.\n\nThe dashboard's safe service-identification workflow accepts up to eight reviewed common TCP ports (21, 22, 25, 80, 110, 143, 443, 445, 587, 993, 995, 8080 and 8443). It requires exact target retyping, an authorisation checkbox and a reference. It reads available FTP/SSH/SMTP/POP3/IMAP banners, sends only HTTP `HEAD /`, and reads TLS certificate metadata on selected TLS ports. It does not log in, guess credentials, transfer files, send exploit payloads or change server state. Each TCP connection has a two-second timeout; `closed_or_filtered` is inconclusive. The planner can prepare a port list for FTP/SSH/SMTP/HTTP/HTTPS/SMB when a candidate target is present, but the user must still confirm scope and start the action.\n\nThe dashboard can request a single-target TCP connect scan with light service-version detection on up to 100 selected TCP ports (custom comma-separated lists or ranges such as `22,80,443` or `1-100`). Results distinguish open, closed and filtered ports when determinable; filtered means no definitive response was possible. The bridge uses fixed Nmap arguments; it does not accept arbitrary command-line options, NSE scripts, exploit checks, credentials, stealth/evasion flags, or shell commands. Each run requires an exact target confirmation, an authorisation reference and an explicit ownership/permission confirmation. Loopback, link-local, multicast and reserved targets are blocked. Private LAN targets may be assessed only when they are in your authorised scope.

Browser access to localhost can depend on browser private-network access policies. If the browser blocks the request, check its site permissions and keep the official CyberLab origin unchanged. The bridge is optional; existing CLI commands continue to work without it.


## Digital forensics and recovery

The dashboard's **Digital Forensics → File & Picture Recovery** module can use this bridge to:
- List block devices using `lsblk` (inventory only; no mounting or writes).
- Require source-device confirmation and reject mounted source partitions.
- Verify that the image destination is a mounted filesystem on a different physical device.
- Create a new image and ddrescue map file without overwriting existing output.
- Run Foremost against a completed CyberLab acquisition image and write results to a new folder on the backup drive.
- Probe a completed image with `blkid` to report recognised filesystem signatures without mounting or modifying the image.
- Enumerate allocated partition boundaries in a completed image with Sleuth Kit `mmls`, without mounting, repairing or modifying it.
- Inspect filesystem metadata for a selected discovered partition with Sleuth Kit `fsstat`; the bridge revalidates the partition start against `mmls` before running a fixed read-only command.

Install the tools with:

```bash
sudo apt update
sudo apt install -y gddrescue testdisk foremost ntfs-3g sleuth-kit
```

For best practice, boot Kali from a live USB, do not boot the installed OS on the affected disk, and do not mount the source partitions. Connect a separate backup drive, then pair the dashboard with the bridge. The acquisition endpoint is allow-listed; it does not accept arbitrary shell commands. It uses GNU ddrescue's first non-scraping pass (`ddrescue -f -n`) and retains the map file so the acquisition can be assessed. Do not disconnect either drive while the job is active. Preserve both the image and the ddrescue-created map file; the map records completed and unreadable regions and is required for a safe resume or follow-up pass. The source device is never an output path.

After imaging, the dashboard can run a read-only Sleuth Kit `mmls` partition-table analysis, a `blkid -p` signature probe, and a selected-partition `fsstat` metadata inspection against the image. The `fsstat` step accepts only a partition start sector returned by a fresh `mmls` parse and limits displayed output to 12,000 characters. It does not mount, repair or modify the image. Partition analysis reports slot, start/end sector, length and partition description for allocated entries; unallocated space and partition-table metadata are excluded. This is boundary discovery only: it does not mount, repair or write to the image, and it does not yet perform filesystem-aware undelete. Install `sleuth-kit` to enable this step.

After imaging, the dashboard can run a read-only `blkid -p` signature probe against the image. This reports recognised filesystem metadata when available; it does not mount the image, modify it, or guarantee that a filesystem is intact. A missing signature is inconclusive. The dashboard can also launch a bounded Foremost recovery job against the image. On successful completion, the companion creates `cyberlab-recovery-manifest.json` inside Foremost's output folder. The manifest records each regular recovered file's relative path, byte size and SHA-256 hash. Symlinks are skipped, enumeration is capped at 5,000 files, and the manifest is created with no-overwrite semantics. A `truncated: true` field means the cap was reached; preserve the Foremost `audit.txt` as well. Hashes document the recovered output as it existed when the manifest was generated; they do not prove authenticity or validate file contents.

PhotoRec remains an interactive recovery option in a separate Kali terminal:

```bash
sudo photorec /mnt/backup/cyberlab-disk.img
```

In PhotoRec, select the image/partition, configure File Opt for the required formats, and choose a recovery directory on the backup drive. NTFS undelete and extundelete workflows are not automated by the dashboard in this release; they require filesystem-specific assessment and an unmounted source. Do not run them against the original disk as a substitute for imaging.

A hosted Vercel deployment cannot directly access the browser user's physical disks. A self-hosted CyberLab AI OS running on a Linux machine can use the same local runner and bridge directly on that machine, provided it has the required OS permissions and tools; no remote web process is given raw-disk access.


## Kali tool catalogue and workflow expansion

The dashboard can submit a natural-language question or task to the authenticated `POST /plan` endpoint. The first-pass planner recognises network reconnaissance, web assessment, DNS/OSINT, vulnerability research, FTP/SSH/SMB and other service enumeration, Metasploit module research, offline password-hash auditing, wireless lab assessment, packet analysis, Active Directory, digital forensics, malware triage, reverse engineering and lab/challenge questions. It extracts at most one explicit URL hostname, IPv4 address or FQDN candidate, lists missing scope/evidence details, checks relevant tool availability, and returns a proposed workflow. It does not scan, connect to, or modify any target. It is deterministic classification, not an AI answer engine; the UI clearly labels it as plan-only.

The dashboard can query the paired local runner's authenticated `GET /tools` endpoint to see which curated Kali tools are installed and how to install missing packages. The inventory is deliberately separate from execution: detecting a binary never causes it to run, and CyberLab never invokes `apt` automatically. The first catalogue covers information gathering, vulnerability analysis, web application analysis, password auditing, wireless security, Metasploit research, traffic analysis, Active Directory, forensics, reverse engineering and network utilities including FTP.

This is the foundation for a natural-language task planner: translate a user's authorised lab question into a bounded plan, verify target/scope, check required tools, ask before package installation, execute only reviewed fixed workflows, collect outputs, and explain the evidence. Tool availability does not imply that every feature is safe for unattended use. CamPhish and comparable phishing/camera-capture workflows are intentionally blocked; online credential guessing, exploit payloads, persistence, interception and post-exploitation are not part of unattended execution. Metasploit integration starts with module search, `info`, option review and safe `check` operations only. A targetless HTB prompt can be analysed for what evidence is needed, but a scan requires a target supplied by the user or a clearly identified in-scope lab endpoint.


### Natural-language task planning

After pairing, open **Kali Connection → Describe any authorised cybersecurity task**. Paste a question, assessment objective, lab prompt or scan request in ordinary language. The planner:
- Classifies the task across multiple security domains rather than being limited to Hack The Box.
- Identifies one explicit candidate URL hostname, IPv4 address or fully-qualified domain name when present.
- Lists the tools that match the task and whether each executable is installed.
- Provides package installation suggestions for missing tools without installing them.
- Identifies missing scope, authorisation, evidence or lab-target information.
- Produces a reviewable workflow and explicitly reports that no execution has started.

The current planner is deterministic and intentionally conservative. It does not infer targets from organisation names, scan broad networks, treat a named host as authorised, or turn pasted text into shell commands. A question without a target can still receive a useful classification and a list of what is needed next. A lab challenge can be analysed from its prompt, but host-specific conclusions require the assigned lab target and evidence from that environment. The next development stage is to add individual fixed workflows behind this plan, beginning with low-impact information gathering and service discovery.


### Evidence-led service and vulnerability-reference analysis

After a successful local service-identification run, choose **Correlate evidence with NIST CVEs**. The authenticated `POST /evidence/report` endpoint accepts the service-identification result (or a previously collected Nmap result) and builds a bounded report containing observed open ports, protocol/service labels, banners, product/version metadata and TLS certificate details. It uses at most three distinct product/version terms for passive NIST NVD keyword searches, with up to ten records per term.

CVE matches are explicitly labelled **unverified reference candidates**. The report does not convert a keyword match, open port, banner or CVSS score into a vulnerability finding. It records lookup failures, confidence context, evidence limitations and safe verification steps. Service names alone do not trigger broad CVE searches when no product/version was identified. No new target connection, exploit check, authentication or configuration change is performed during correlation.

The report is only as reliable as the evidence supplied to it. Confirm exact vendor, product, version, configuration and patch state against the asset owner and official vendor advisories before making a finding. This stage is evidence correlation, not an automated vulnerability verdict.
