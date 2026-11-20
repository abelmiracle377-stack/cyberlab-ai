# CyberLab AI Kali Companion

A command-line research companion for Kali Linux and other Linux distributions. It adds passive OSINT, public vulnerability intelligence, and an optional authenticated loopback bridge that lets the hosted CyberLab dashboard request explicitly authorised local Nmap checks. Python 3.9+; Python standard library only; no pip packages or API keys. Optional `figlet` and `chafa` packages provide the large coloured startup lettering and terminal mascot artwork.

## Install

```bash
git clone https://github.com/abelmiracle377-stack/cyberlab-ai.git
cd cyberlab-ai
sudo apt update && sudo apt install -y figlet chafa nmap openssl gddrescue testdisk foremost ntfs-3g sleuth-kit
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


### Local Solidity compiler (optional)

The paired bridge exposes `GET /solidity/compiler` for read-only discovery and `POST /solidity/compile` for an explicit local compile request from Solidity Lab. Install a trusted Solidity compiler yourself and pin the version to the project's declared compiler; the bridge never downloads or installs compilers and accepts no user-supplied executable path. Compilation uses only the fixed `solc --standard-json` interface, one in-memory source file, a 100 KB source limit, a 30-second timeout, bounded output, and conservative Linux process limits where supported. Imports and external dependency resolution are rejected in this initial stage. The source is sent from the browser directly to the loopback companion, not to CyberLab's hosted API. Compiler warnings/errors are diagnostics, not an audit; generated bytecode is not deployed or signed. The bridge is not a complete OS sandbox, so compile only source you trust.


### Isolated Solidity test runner (optional, fail-closed)

The paired bridge exposes GET /solidity/tests/status and POST /solidity/tests/run. Execution requires rootless Podman and a locally preloaded Foundry image configured through CYBERLAB_FOUNDRY_IMAGE as a full image reference ending in @sha256:<64-hex-digest>. The bridge verifies rootless mode and local image presence, uses --pull=never, and never installs or downloads a runtime or image. Docker and direct host execution are not fallback options.

The current test stage accepts 2–100 project files and 500 KB combined, including flat src/*.sol and test/*.t.sol files plus nested OpenZeppelin Contracts 5.x source files. It validates the exact same SHA-256 dependency lock used by multi-file compilation, generates a local Foundry remapping, and rejects unpinned dependencies, forge-std and unsupported imports. The fixed container invocation disables networking, uses a read-only image filesystem, drops capabilities, enables no-new-privileges, and caps memory (1 GiB), CPU (1 core), processes (64), execution time (120 seconds), and captured output (256 KB). Project files are mounted into a temporary workspace and removed after the run. This is a constrained local sandbox, not a formal isolation guarantee; use a trusted image and review tests before execution. The image must already contain the matching Foundry and solc versions; no compiler or dependency is downloaded. Passing tests are not an audit or proof of correctness.

Example environment configuration (replace with a digest independently verified and loaded locally):

    export CYBERLAB_FOUNDRY_IMAGE='registry.example/foundry@sha256:REPLACE_WITH_VERIFIED_64_HEX_DIGEST'


### Multi-file Solidity compilation and pinned OpenZeppelin source

The paired bridge exposes POST /solidity/project/compile. It accepts 1–100 in-memory Solidity files (500 KB combined), source files under flat src/*.sol or test/*.sol paths, and OpenZeppelin package files under lib/openzeppelin-contracts/contracts/. It supports only @openzeppelin/contracts 5.x.y, with a dependency lock containing the exact version, canonical repository URL, a full commit identifier, and a SHA-256 digest for every supplied package source file. Every library file must be covered by the lock; unpinned or unknown dependency paths are rejected. Imports must resolve to supplied project files or the pinned OpenZeppelin package. The compiler uses standard JSON and a fixed local solc executable. No package is downloaded, installed or executed.

The SHA-256 check establishes that submitted source bytes match the submitted lock entries; it does not independently prove that the first downloaded source came from the declared Git commit or release. Obtain source from the official OpenZeppelin repository, independently verify its release tag/commit and file contents, and review/protect the lockfile before use. The UI's prefilled project text contains placeholders, not a complete OpenZeppelin package; replace them with the complete dependency closure and a matching lock before compiling.

Multi-file compilation is not a test run, audit, deployment or proof of correctness.


### Offline Foundry tests with pinned OpenZeppelin sources

POST /solidity/tests/run accepts the same dependencyLock format as /solidity/project/compile. The runner accepts 2–100 files and 500 KB combined, including flat src/*.sol and test/*.t.sol files plus explicitly locked files under lib/openzeppelin-contracts/contracts/. It validates exact SHA-256 digests, rejects unpinned library files and unsupported imports, and writes a generated Foundry configuration with the OpenZeppelin remapping and local lib directory. Foundry runs in the preloaded digest-pinned rootless Podman image with --pull=never, --network=none and --offline. No package manager, network fetch, dependency install or host fallback is used.

Only @openzeppelin/contracts 5.x is supported. forge-std and other dependencies are not accepted by this workflow; tests should use Foundry's built-in test discovery/assertions unless another dependency is separately reviewed and implemented. The image must already contain a suitable Foundry toolchain and the exact solc compiler version required by the project; compiler auto-detection cannot download a missing compiler in this offline environment. The runner does not independently attest the image contents or the source-to-Git-commit provenance of a submitted dependency lock. Verify and pin both independently. A passing test suite is not an audit or proof of correctness.


### NFT and AMM teaching fixtures

The repository includes self-contained examples under examples/solidity. The capped collection fixture covers owner-only minting, a hard supply cap, approval transfer and a safe-receiver callback. The constant-product pool fixture covers 0.3% swap fee arithmetic, reserve accounting, minimum output, deadline checks, proportional liquidity shares and withdrawal. Their Foundry tests use Solidity's built-in assert statements and do not depend on forge-std.

These examples are deliberately simplified teaching fixtures, not complete ERC-721/ERC-20 standards implementations, audited AMMs or deployable production contracts. The companion CI validates their project-relative import graphs but does not run a real solc or Foundry process. Run each project locally through the multi-file compiler and offline Foundry sandbox using an independently verified, digest-pinned image containing solc 0.8.20 and Foundry.
## Digital forensics and recovery

The dashboard's **Digital Forensics → File & Picture Recovery** module can use this bridge to:
- List block devices using `lsblk` (inventory only; no mounting or writes).
- Require source-device confirmation and reject mounted source partitions.
- Verify that the image destination is a mounted filesystem on a different physical device.
- Create a new image and ddrescue map file without overwriting existing output.
- Carve files from a completed CyberLab acquisition image with Foremost (`POST /forensics/foremost`; the carve type list is configurable via `fileTypes`, defaulting to a broad photo/video/audio/document/archive set) and write results to a new folder on the backup drive.
- Carve with PhotoRec (`POST /forensics/photorec`) for far broader format coverage (480+ types, including HEIC, camera RAW, MP4 and Office files) when filesystem metadata is gone. Background job, SHA-256 manifest, output on a different drive.
- Probe a completed image with `blkid` to report recognised filesystem signatures without mounting or modifying the image.
- Enumerate allocated partition boundaries in a completed image with Sleuth Kit `mmls`, without mounting, repairing or modifying it.
- Inspect filesystem metadata for a selected discovered partition with Sleuth Kit `fsstat`; the bridge revalidates the partition start against `mmls` before running a fixed read-only command.
- List deleted files in a completed image with Sleuth Kit `fls -r -p -d` (optionally scoped to a selected partition offset), preserving their original names and paths, and recover any one by inode with `icat` to a destination on a different physical drive (owner-only output, SHA-256 hashed).
- Recover every deleted file in one step with `POST /forensics/recover-all-deleted`: it lists deleted entries (`fls`) and extracts each (`icat`) to a new folder on a different drive, keeping original names, with a SHA-256 for every file and a recovery manifest. Bounded by `maxFiles`; one unreadable file never aborts the batch.

Install the tools with:

```bash
sudo apt update
sudo apt install -y gddrescue testdisk foremost ntfs-3g sleuth-kit
```

For best practice, boot Kali from a live USB, do not boot the installed OS on the affected disk, and do not mount the source partitions. Connect a separate backup drive, then pair the dashboard with the bridge. The acquisition endpoint is allow-listed; it does not accept arbitrary shell commands. It uses GNU ddrescue's first non-scraping pass (`ddrescue -f -n`) and retains the map file so the acquisition can be assessed. Do not disconnect either drive while the job is active. Preserve both the image and the ddrescue-created map file; the map records completed and unreadable regions and is required for a safe resume or follow-up pass. The source device is never an output path.

After imaging, the dashboard can run a read-only Sleuth Kit `mmls` partition-table analysis, a `blkid -p` signature probe, and a selected-partition `fsstat` metadata inspection against the image. The `fsstat` step accepts only a partition start sector returned by a fresh `mmls` parse and limits displayed output to 12,000 characters. It does not mount, repair or modify the image. Partition analysis reports slot, start/end sector, length and partition description for allocated entries; unallocated space and partition-table metadata are excluded. This is boundary discovery only: it does not mount, repair or write to the image. Filesystem-aware undelete is available as a separate step: `POST /forensics/deleted-list` enumerates deleted entries (names, paths, inodes) with `fls`, and `POST /forensics/recover-file` extracts a chosen inode with `icat` to a different drive. Install `sleuth-kit` to enable both steps.

After imaging, the dashboard can run a read-only `blkid -p` signature probe against the image. This reports recognised filesystem metadata when available; it does not mount the image, modify it, or guarantee that a filesystem is intact. A missing signature is inconclusive. The dashboard can also launch a bounded Foremost recovery job against the image. On successful completion, the companion creates `cyberlab-recovery-manifest.json` inside Foremost's output folder. The manifest records each regular recovered file's relative path, byte size and SHA-256 hash. Symlinks are skipped, enumeration is capped at 5,000 files, and the manifest is created with no-overwrite semantics. A `truncated: true` field means the cap was reached; preserve the Foremost `audit.txt` as well. Hashes document the recovered output as it existed when the manifest was generated; they do not prove authenticity or validate file contents.

PhotoRec now runs directly from the dashboard (`POST /forensics/photorec`) as a bounded background job against the verified image, carving 480+ formats to a new folder on the backup drive with its own SHA-256 manifest. Choose the recovery approach by filesystem state: use the `fls`/`icat` named undelete (individually or the one-step `recover-all-deleted`) to recover deleted files with their original names on an intact filesystem, and PhotoRec or Foremost to carve by signature from a damaged or reformatted filesystem. The companion always refuses to write recovered output onto the original source device.

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


### Static artifact and recovery-manifest evidence

The authenticated `POST /evidence/artifacts` endpoint accepts bounded JSON from the companion's existing static `triage` command or the SHA-256 recovery manifest. It validates the file hash, size and entropy fields, limits indicator arrays, checks manifest paths against traversal, rejects malformed hashes, and summarises recovered file extensions, sizes and hashes. The analysis never opens or executes a sample; it does not upload files or contact third-party reputation services.

The report keeps heuristic string indicators and entropy separate from conclusions. High entropy may reflect ordinary compression or encryption, and a matching string is only a prompt for contextual review. The recovery manifest proves only that listed bytes matched the recorded hashes when the manifest was created; it does not prove file authenticity, original filenames or safe contents. No automatic malware verdict or risk finding is issued. The Kali dashboard includes a paste-in JSON panel for a triage result or recovery manifest so this analysis can be used without adding a sample-upload path.


### Unified investigation case and local audit ledger

After creating a network evidence report and/or static artifact report, use **Unified investigation case** in the Kali dashboard. The authenticated `POST /evidence/case` endpoint combines completed reports, preserves their source-level confidence and limitations, records source SHA-256 digests, and returns a case identifier and timestamp. It deliberately does not upgrade heuristic observations into confirmed vulnerability or malware findings.

Each case creation appends one metadata-only JSONL record to `~/.local/state/cyberlab/case-audit.jsonl`. The directory is created with mode 0700 and the file with mode 0600 where supported. A file lock serialises writers, records are appended and fsynced, and each record includes the previous record hash. Before a new record is appended, the companion verifies the entire existing hash chain and refuses to continue if it detects malformed or altered records. The ledger has a 5 MB cap. It stores case identifiers, timestamps, source types and evidence digests—not raw banners, CVE descriptions, samples, credentials or recovered file contents.

This is a local integrity-evident audit aid, not a digitally signed or tamper-proof chain of custody. A privileged local administrator can still replace the ledger or its host. Export and preserve the ledger under the organisation's evidence-retention policy, and retain original evidence separately. Add analyst identity, authorisation reference, scope, collection time and tool versions in the formal case-management process.


## Native Network Intelligence and packet capture

The paired dashboard includes a **Network Intelligence** workspace at `/network-intelligence`. It is independent of Burp Suite and uses the local `tcpdump` executable through the authenticated loopback bridge.

- `GET /network/interfaces` lists interface names and operational state only.
- `POST /network/capture` performs one short passive capture on an exact, re-confirmed interface.
- Supported fixed filters: SSH/TCP port 22, DNS/port 53, TCP, UDP and ICMP/ICMPv6.
- Maximum duration: 30 seconds. Maximum packet count: 2,000. Snap length: 96 bytes.
- Each capture requires the bridge pairing token, exact interface retyping, an explicit authorisation confirmation and an engagement/lab reference.
- PCAP files remain on the paired workstation under `~/.local/share/cyberlab/captures/`, with owner-only permissions and a SHA-256 evidence hash.
- Only packet counts, protocol counts and bounded endpoint metadata are returned to the dashboard. Packet payloads are not forwarded to the AI.

Install tcpdump separately if needed: `sudo apt install -y tcpdump`. The companion does not install it, invoke sudo or change interface capabilities. The bridge process must already have the OS permissions required for packet capture. Use only on networks you own or are authorised to monitor.

The SSH filter captures TCP port 22 traffic. Packet capture can show endpoints and handshake metadata, but encrypted SSH session data does not expose passwords, commands or terminal contents. This first slice does not yet import external PCAP/PCAPNG files, reconstruct streams, perform deep TShark dissection or run AI anomaly detection. See `docs/NETWORK_INTELLIGENCE.md` for the detailed API and safety boundary.


## Native web assessment

CyberLab includes a native HTTP workbench and a bounded same-origin web crawler/baseline auditor. The crawler sends approved GET requests only, revalidates target scope for every page, blocks out-of-origin links and redirects, inventories forms without submitting them, and reports baseline header/cookie indicators. It does not perform payload-based vulnerability testing. See `docs/NATIVE_WEB_WORKBENCH.md` for current capability boundaries.


CyberLab also includes limited native safe active web checks for CORS preflight and inert GET query-reflection indicators. These are bounded and approval-gated; they do not constitute a full exploit scanner. See `docs/NATIVE_WEB_WORKBENCH.md` for the current scope and limitations.

The native HTTP workbench can reload request history for a newly approved replay. Sensitive request headers are redacted and request-body contents are deliberately omitted from history; operators must re-enter any body before replay.

A native HTTP/HTTPS interception proxy is available from the Web Workbench. It binds only to 127.0.0.1, requires one exact approved origin and explicit start approval, and supports HTTP/1.1 plus HTTPS CONNECT TLS termination with the CyberLab-managed local CA. Create the CA explicitly in the workbench and manually trust its public certificate in a dedicated test browser profile; CyberLab does not alter system/browser trust stores. Proxy history omits request/response bodies and URL queries and redacts sensitive headers. Optional manual request interception pauses traffic in a bounded queue; operators can forward unchanged, edit eligible methods, paths, headers and UTF-8 bodies before forwarding, or drop requests. Response interception can separately pause, inspect, edit eligible status/header/text-body fields, forward or drop. Both queues are bounded and undecided items are dropped after 120 seconds. POST, PUT, PATCH and DELETE are blocked unless separately approved at proxy start. The native `/web-repeater` workspace supports up to five request tabs, explicit per-send approval, response inspection/comparison and bounded offline parameter mutation drafts. Current proxy limitations include one request per client connection, no HTTP/2, WebSockets, chunked client request bodies, client certificates or multi-origin profiles.


## Vetted tool execution and agent operation

Beyond the plan-only `POST /plan` endpoint, the companion can **run** a curated set of security tools through `POST /tools/run` (discover availability with `GET /tools/runners`). This is a vetted execution layer, not an arbitrary shell:

- Each tool has a fixed argument template; operator input only fills validated, typed slots (hostname/IP, URL, port spec, single port, wordlist path, bounded integers, injection-safe search terms). No value is ever passed through a shell.
- Each tool has a fixed argument template; operator input only fills validated, typed slots (hostname/IP, URL, port spec, single port, wordlist path, local file path, hash string, bounded integers, injection-safe search terms). No value is ever passed through a shell.
- **Passive tools** (whois, dig, host, dnsrecon, dnsenum, fierce, sublist3r, theHarvester, Metasploit module search) run after an explicit confirmation. This also covers **local-file forensics** that operate only on a file you supply, not a network target: ExifTool metadata extraction, binwalk signature/firmware carving, `strings`, and offline hash-type identification (hashid).
- **Active tools** (nmap TCP/UDP, masscan, sslscan, tlsx, netcat banner grab, ftp anonymous listing, whatweb, wafw00f, nikto, nuclei, wpscan, gobuster, ffuf, dirb, sqlmap, enum4linux-ng, smbmap, smbclient share listing, rpcclient server info, nbtscan, ssh-audit, fping, arp-scan, onesixtyone SNMP, showmount NFS, anonymous LDAP naming contexts, ike-scan, cewl) additionally require a written authorisation reference and an exact-target confirmation, mirroring the Nmap scan flow.
- If a tool's binary is not installed the call fails closed with an apt install hint; output is bounded and is only ever the tool's own stdout/stderr and exit code.
- Metasploit is limited to module **search** metadata; unattended exploit execution and online brute-force remain out of scope.

The hosted AI agent console can turn an instruction such as "run whois on example.com" or "nikto https://app.example.com" into a concrete `POST /tools/run` request that the operator approves in the browser; the browser calls the local bridge with the paired token and feeds the real output back to the model for analysis. The server-side agent never reaches the loopback bridge directly. The dashboard's Tool Runner page offers the same execution from a form instead of the agent.

**Tool availability by platform.** Tools execute for real — `subprocess.run` with a fixed argument list, no shell — but only when the binary is installed on the machine running the companion:

- On **Kali Linux**, all of these tools are available from Kali's repositories, so the full set can run.
- On the **Debian-based CyberLab OS VM**, the live/VM profiles ship the Debian-packaged subset (nmap, sqlmap, nikto, gobuster, dirb, sslscan/sslyze, masscan, hydra, john, hashcat, aircrack-ng, wpscan, smbmap, nbtscan, ssh-audit, dnsenum, fierce, sublist3r, theHarvester, wafw00f, dnstwist, testssl.sh, ffuf, whois, dig/host and more). Go/ProjectDiscovery and Kali-only tools (httpx, naabu, katana, subfinder, amass, nuclei, feroxbuster, dalfox, gau, waybackurls, assetfinder, gospider, arjun, cmseek, droopescan, joomscan, searchsploit/exploitdb, metasploit-framework) are not in Debian and are not shipped on the OS VM; run the companion on actual Kali for those, or install them manually. Either way, a missing tool fails closed with an install hint — never a simulated result.

Wireshark's `tshark` capture analysis is exposed at `POST /network/pcap-analyze` (protocol hierarchy and top IP conversations over an existing .pcap/.pcapng). The Wireshark GUI itself runs on the Kali/OS machine, not through the companion.

**Host telemetry.** `GET /telemetry/security` reports listening sockets and interactive sessions; `GET /telemetry/system` adds a read-only system-posture summary — OS/kernel, uptime, load average, memory and disk usage, and recent/failed logins (with source IPs where present). Both read the local host only with fixed read-only commands and `/proc` reads (no shell), return bounded structured results, and collect no file contents, process command lines or network payloads. Failed-login history (`lastb`) needs root and is reported as such rather than failing when it is unavailable.

## Local wallet recovery

The dashboard's **Wallet Recovery** module can use the companion for owned or explicitly authorised backups:

- `POST /wallet/derive` performs standards-based BIP39/BIP32/BIP44 derivation (verified against the official BIP32/BIP39/EIP-55 vectors) to list addresses and keys for a supplied mnemonic — Python standard library only, no network. Supported account types: Bitcoin legacy/BIP49 nested SegWit/BIP84 native SegWit, Litecoin (legacy/nested/native SegWit), Dogecoin, Bitcoin Cash (CashAddr, verified against the CashAddr reference vector), and Ethereum. A BIP39 passphrase (25th word) is supported.
- `POST /wallet/auto-recover` is the one-call "I don't know what kind of seed this is" path: it detects the scheme (Electrum v2 standard/segwit, Electrum old, else BIP39), derives with the right scheme across accounts and change chains, and — when a phrase could be BIP39 or old Electrum — returns both candidate sets. With `checkBalances` + `confirmNetwork` it reports which path across every candidate holds funds. 2FA Electrum seeds are reported as unrecoverable from the seed alone.
- `POST /wallet/sweep` derives across account indices (0..N) and both the receiving and change chains for each template, so recovery finds funds that sit on account 1+ or on change addresses rather than the first receiving address. With `checkBalances` + `confirmNetwork` it reports which derivation paths actually hold funds.
- `POST /wallet/derive` flags an Electrum v2 seed (detected by its HMAC-SHA512 "Seed version" prefix) with a `warning`, since BIP39/BIP44 derivation cannot reproduce an Electrum wallet.
- `POST /wallet/electrum-derive` recovers an Electrum wallet directly from its seed, auto-detecting the scheme: v2 **standard** (legacy P2PKH, `m/{change}/{i}`), v2 **segwit** (P2WPKH, `m/0'/{change}/{i}`), or **old/pre-2016** (12 words from the bundled, SHA-256-verified 1626-word list — or a 32-char hex seed — stretched 100k rounds into a master-public-key sequence chain of uncompressed P2PKH addresses). All three are verified against Electrum's own receiving/change test vectors. 2FA (TrustedCoin) seeds are reported as unrecoverable from the seed alone.
- `POST /wallet/extract-hash` with `kind: "metamask"` extracts a hashcat `-m 26600` hash from a MetaMask browser vault (the raw `{data, iv, salt}` object or an export that nests it), alongside Ethereum keystore and Bitcoin Core `wallet.dat`.
- `POST /wallet/bip38-decrypt` decrypts a BIP38 encrypted private key (`6P...`, no-EC-multiply) with a known passphrase, and `POST /wallet/bip38-crack` tries a local passphrase list against one. Both run fully offline with a dependency-free AES-256 core (verified against FIPS-197) plus `hashlib.scrypt`, and are verified against the BIP38 specification's own test vectors; a wrong passphrase is reported via the key's embedded address hash rather than returning a bogus key. EC-multiply keys are reported as unsupported.
- `POST /wallet/solve-seed` reconstructs a mnemonic that is missing words (mark each blank `?`/`_`; every 2048 candidates per blank are tried and only checksum-valid phrases kept) or out of order (bounded permutation search). An optional known address pins the single correct phrase via real derivation. Loads your own SHA-256-verified BIP-39 `english.txt`. A hard combination cap and time budget keep a search from hanging.
- `POST /wallet/extract-hash` extracts a hashcat/John hash from an Ethereum V3 keystore or a Bitcoin Core `wallet.dat` master key.
- `POST /wallet/crack` runs a locally installed hashcat or John against the extracted hash. hashcat supports dictionary (`-a 0`, optional rules file), mask (`-a 3`, with up to four custom charsets), and the wordlist+mask hybrids (`-a 6`/`-a 7`); John supports wordlist mangling rules (`--rules`) and incremental mode. A recovered password is only ever reported from the tool's own output; the companion never downloads cracking tools and fails closed when they are absent.
- `POST /wallet/check-balances` is an opt-in (`confirmNetwork`), read-only lookup via an allow-listed public explorer. It derives-then-checks from a mnemonic (or checks supplied addresses) to show which derivation path and coin hold funds or show prior activity. Only public addresses are sent — never a key, seed or mnemonic.

## Burp Suite connector

The local Montoya extension exposes read-only in-scope proxy history, site map and audit issues, plus two write actions gated by explicit confirmation: placing a request in Repeater (`/burp/repeater/from-history`, which does not send) and replaying a single in-scope request through Burp (`/burp/send-request`, which returns status/MIME/length only). Out-of-scope requests are refused. Intruder, crawling and scan-start remain out of scope.
