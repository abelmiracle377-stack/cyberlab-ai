# CyberLab AI Kali Companion

A command-line research companion for Kali Linux and other Linux distributions. It adds passive OSINT and public vulnerability intelligence to the original local evidence tools. Python 3.9+. Core modules use the Python standard library. Install the optional `phonenumbers` package for deeper offline numbering-plan metadata (validity, line type, original carrier-range label and approximate numbering region). Optional `figlet` and `chafa` packages provide startup artwork.

## Install

```bash
git clone https://github.com/abelmiracle377-stack/cyberlab-ai.git
cd cyberlab-ai
sudo apt update && sudo apt install -y figlet chafa python3-venv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip phonenumbers
python3 kali-companion/cyberlab.py doctor
python3 kali-companion/cyberlab.py menu
python3 kali-companion/cyberlab.py --help
```

## 21-option Kali command centre

Launch the full local-first menu:

```bash
python3 kali-companion/cyberlab.py menu
```

The menu exposes 21 separately numbered operations, including research tools, manual assessment, evidence management, password and authentication review, phone-number metadata, and dedicated username, password-policy, MFA and isolated credential-guessing lab modules. URL analysis performs bounded public DNS, TLS certificate and single-page HTTPS metadata checks, plus optional Google Safe Browsing threat-list lookup. It strips query values/fragments, does not follow redirects, execute JavaScript, submit forms or download files. Requests originate from the Kali machine; this is not a cloud sandbox. File and image analysis uses static signature/hash/string triage; it does not execute files or guarantee a malware verdict.

Device pairing and remote connected-device listing remain unconfigured. The separate Global Camera Intelligence module (option 21) supports owner-authorised RTSP viewing, bounded private-LAN service discovery, and location-specific searches of operator-published public webcam directories. Option 3 creates targeted location search links and can return individual camera-page URLs from Windy's official webcam catalogue when configured with an API key. To enable structured Windy results, obtain a Windy Webcams API key and set it before launching CyberLab:

```bash
export WINDY_WEBCAMS_API_KEY="your-windy-webcams-api-key"
python3 kali-companion/cyberlab.py menu
```

The Windy integration geocodes the entered place and searches a 100 km radius, returning published camera pages and provider live-status metadata where supplied. Without the key, the tool still produces location-specific search links for EarthCam, SkylineWebcams, Explore.org and Windy. It never scans arbitrary public IP ranges, enumerates unsecured private CCTV, bypasses authentication or opens private feeds.

Camera Intelligence also includes option 4, **Camera Exposure Assessment & Defence**. This additive, offline checklist records operator answers about internet exposure, remote administration, HTTPS, unique credentials, MFA, firmware support, UPnP/port forwarding, network segmentation and security logging. It produces a triage score, remediation guidance, verification tasks and a responsible-disclosure message template. Answers are self-reported and are not technical proof of exposure; this option makes no network connections and does not access video streams.

## Interactive command centre

Launch the local menu-driven interface:

```bash
python3 kali-companion/cyberlab.py menu
```

Choose Domain OSINT, DNS, Manual Security Assessment & Verification, public IP intelligence, CVE research, static file triage, Nmap XML analysis, or local investigation history. Successful results are saved as timestamped JSON files under `~/CyberLab/investigations/`. Reports remain on the Kali machine and are not uploaded automatically. The menu does not execute arbitrary shell commands or start network scans.

## Commands

| Command | Input | What it does |
|---|---|---|
| `domain example.com` | Public domain | RDAP registration dates, certificate-transparency names, DNS A/AAAA/MX/NS/TXT records, and a bounded public HTTPS landing-page profile (title, description, public business contact details, social links, visible login-form fields and security headers) |
| `dns example.com` | Public domain | A, AAAA, MX, NS and TXT lookups using public DNS-over-HTTPS |
| `ip 8.8.8.8` | Public global IP | RDAP network registration context |
| `cve "OpenSSH"` | Product/vendor/version/CVE keyword | Searches NIST NVD and returns CVE descriptions and available CVSS severity |
| `triage ./file.exe` | Local file, max 10 MB | SHA-256, file signature, entropy and selected printable-string indicators |
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
- DNS: Cloudflare public DNS-over-HTTPS (DNS JSON response negotiation).
- IP registration: RDAP via rdap.org.
- Vulnerabilities: NIST National Vulnerability Database API.
- File triage and Nmap XML parsing run locally.

The domain/IP/DNS/CVE commands make read-only requests to the named public data providers. They do not scan target hosts. The companion does not perform subdomain brute forcing, exploit attempts, credential attacks, stealth, persistence, shell execution, sample execution or private-person identification. Use network assessment features only with explicit authorisation; the XML parser only reads a report you already have.

## Interpretation

RDAP identifies the organisation/network associated with an address range, not a specific person's identity or exact location. Certificate-transparency names may be historical or wildcard entries and need validation. CVE matches are search results, not proof that a particular host is vulnerable. Static indicators are not a malware verdict.

## Limits

HTTP timeout defaults to 12 seconds and can be changed with `--timeout 20`. JSON output can be saved with `-o report.json` or `--output report.json`. Public data providers can rate-limit or be temporarily unavailable. No API keys are required.


### Domain and IP intelligence scope

Domain research fetches only the supplied domain's public HTTPS home page (up to 1 MB) after passive RDAP, certificate-transparency and DNS lookups. It does not crawl pages, enumerate admin paths, submit login forms, test SQL injection, attempt passwords, or exploit session handling. A visible password field is only a form observation, not a vulnerability result. Missing security headers are review signals, not proof of exploitability. Public page metadata cannot reliably prove that a website was built with AI.

IP research summarises public RDAP network registration, registry dates, country and published network/abuse contacts where available. Public IP records cannot reveal the last time a device connected, websites a subscriber visited, or the identity of a person behind a shared/dynamic IP. Those facts require authorised logs held by the relevant service or network operator.


## Manual Security Assessment & Verification (menu option 3)

This guided assessment is for systems you own or are explicitly authorised to review. It can optionally make one read-only HTTPS GET to an explicitly supplied, owner-approved page to inspect visible form fields, classify common email/password or username/password form patterns, and record response security headers and cookies (Secure, HttpOnly, SameSite). It can make one HEAD request to an explicitly supplied admin URL to record response status and selected metadata; it never follows redirects or guesses paths.

These observations do not prove backend authentication or authorization. Rate limiting, account lockout, session rotation/expiry, SQL query safety and role enforcement still require source/configuration review or owner-provided evidence. SQL injection guidance explains the flaw, impact and parameterized-query remediation. No login, form submission, attack payload, brute-force attempt, credential collection or session manipulation is performed. Reports are saved locally under `~/CyberLab/investigations/`.


## Password & Authentication Security (menu option 14)

The defensive password module provides:
- Local password-strength signals using hidden terminal input; the password itself is not returned or saved.
- Strong random password generation for setting a NEW account password or completing a reset. The generated plaintext is displayed once and deliberately excluded from saved reports.
- Clearly labelled `<lab>-test-01` style usernames for provisioning accounts in your own isolated lab; these are not candidate usernames for guessing existing accounts.
- Password-storage metadata review (algorithm family, salt usage and documented work-factor/parameters). Do not paste plaintext passwords or password hashes into the tool.
- Operator-led review of rate limiting, progressive delay/lockout, MFA, breached-password blocklists and password-reset controls.
- Read-only website login-surface inspection: enter an explicitly authorised public HTTPS login URL; CyberLab performs one bounded GET (no redirects) and a TLS handshake, parses visible authentication forms (method, action/origin, password/email/username fields, autocomplete, hidden token-name indicators and required fields), inventories scripts and external script integrity hints, checks mixed-content references, cookie attributes and expanded security headers, and reports TLS certificate issuer/subject/SAN/expiry/protocol/cipher plus evidence-based observations. It does not submit forms, authenticate, crawl routes or execute JavaScript.
- John the Ripper integration for authorised offline hash audits using a local hash file and a chosen wordlist (RockYou can be selected). John runs locally; the temporary pot file is deleted and recovered plaintext passwords are never included in reports.
- Optional local authentication-log analysis remains available for exported server/WAF/identity-provider evidence; it is not required for website investigations.

CyberLab includes a Hydra-style local credential-guessing simulation at top-level option 17. It reads a local wordlist and compares candidates against a synthetic password entered by the operator, displays candidate progress, and can model an MFA-required outcome. It does not invoke Hydra, send HTTP requests, contact a real account, or establish whether an external service is vulnerable. The website workflow remains a read-only authentication-surface preflight.


## Law Enforcement & Scam Investigation (menu option 15)

This is a public-source and evidence-review workspace, not an account-access tool. It provides:
- Public scam-site intelligence using RDAP, DNS, certificate-transparency records and the supplied domain's public homepage.
- One explicitly supplied HTTPS page inspection using a read-only GET; redirects are not followed and forms are never submitted.
- Website-first login assessment: option 3 accepts an authorised public HTTPS login URL and performs a read-only inspection. It does not ask for a local log file.
- John the Ripper offline auditing: option 4 accepts an authorised local hash inventory and wordlist, with automatic hash-format detection or an optional John format override. Only aggregate cracked/remaining counts are retained; plaintext results and the temporary pot file are discarded.
- Optional forensic tools remain available under options 8 and 9: exported authentication-log analysis and hash-format inventory classification.
- Public digital-footprint research, page inspection, and locally saved evidence notes remain available.

**Important boundary:** the credential-guessing lab at option 17 is an offline simulation only; it does not attack live websites, bypass authentication or access accounts. The read-only website inspection is deeper than a header check, but it still cannot prove server-side password handling, SQL injection resistance, rate limiting, lockout, MFA, session rotation/expiry, logout invalidation or role enforcement. Those require source/configuration review, owner-provided logs or a separately authorised staging test. John is restricted to offline hashes the operator owns or is explicitly authorised to audit. Public indicators are leads, not attribution or proof of criminal activity.


## Dedicated authentication security options (menu options 17-20)

These features are separate top-level menu entries rather than being hidden inside the password or investigation submenus:

- **17 — Hydra-Style Credential Guessing Lab:** reads a local wordlist and compares each candidate with a synthetic lab password entered through hidden terminal input. Progress is displayed as candidates are checked. The operator can simulate MFA so a password match does not imply completed authentication. The lab accepts a maximum of 50,000 candidate comparisons and a 25 MB wordlist. It never invokes Hydra, sends network requests, contacts a real account or saves the supplied password.
- **18 — Username Privacy Assessment:** checks a supplied username string for privacy-risk patterns such as birth-year-like sequences or personal-identifier hints. It does not check account existence or enumerate users.
- **19 — Password Policy Assessment:** records operator-reported minimum length, breached-password blocklist, reuse-prevention and reset-protection settings.
- **20 — Automated MFA / 2FA Target Assessment:** asks for the exact authorised HTTPS login URL and the account email address, then inspects that page's TLS certificate, visible login/MFA form indicators and security metadata, and checks public MX/SPF/DMARC records for the email domain. The full email address is masked in the report and is never sent to a remote lookup service. It does not ask the operator to self-report MFA settings. A public page cannot prove that the named account has MFA enrolled or that the identity provider enforces it; account-level confirmation requires authorised identity-provider admin evidence or authentication logs.

Options 14 and 15 remain available with their existing password/authentication and scam-investigation workflows. These new options are additive; they do not renumber or remove existing menu items.

## Additional defensive research improvements

- **CVE research:** NVD results now include CVSS vectors, weakness identifiers (CWE), reference links and affected CPE/version-boundary metadata when the API provides them. A keyword match is not proof that an installed asset is vulnerable; verify the exact product build and configuration.
- **Static file triage:** rejects symbolic links, checks the file-size limit before reading, flags known extension/signature mismatches and adds a cautious entropy interpretation. It remains static-only and does not execute, unpack, activate macros or upload samples.
- **Nmap XML analysis:** adds open-service counts and a compact inventory of reported product/version banners. Banners can be inaccurate; verify actual installed versions before CVE matching. No scan is launched.
- **Evidence manager:** can copy an explicitly selected local file (up to 10 MB) into the local evidence folder, label it with a case reference and create a SHA-256 manifest. The new integrity check recomputes hashes and reports missing or changed evidence without modifying it.
- **Investigation reports:** existing timestamped local JSON report saving remains unchanged. Evidence-integrity results can also be saved as a report.
- **Password security and scam investigation:** existing defensive review and public-source/local-evidence workflows are retained; no cracking, password guessing, credential collection, account access or attribution claims are introduced.

Evidence files may contain sensitive material. Keep the evidence directory access-controlled, avoid storing passwords/session tokens, and preserve original source files separately when chain-of-custody requirements apply.

- **Investigation report integrity:** each new local JSON report now receives a SHA-256 sidecar manifest. The report history includes a verification action that identifies missing or changed reports. Timestamp precision and exclusive file creation reduce accidental same-name overwrites. This detects changes against the local manifest; it is not a digital signature or a substitute for formal chain-of-custody procedures.
- **Scam-investigation evidence notes:** notes now include a case reference, UTC timestamp, note fingerprint and safer source-reference metadata. Query strings and URL fragments are omitted from recorded public URL references to avoid accidentally saving tokens. A URL reference is not fetched or independently verified.

- **Case timelines:** the Evidence Manager can append case events (observation, collection, review, etc.) to a local JSONL timeline. Each event includes a UTC timestamp, source reference, previous-entry hash and SHA-256 entry fingerprint. The timeline can be viewed and its hash links verified. This is a local tamper-evidence aid, not a trusted timestamp, immutable log, external checkpoint or formal chain-of-custody system; final-entry deletion cannot be detected without an external anchor.

- Case timeline entries are hash-linked and can be verified before use. New entries are refused if an existing timeline fails verification. HTTP(S) source references are stored without query strings or fragments, and URLs with embedded credentials are rejected. This reduces accidental token retention but does not make the local timeline immutable or externally timestamped.

- **Type-specific DNS Intelligence (menu option 2):** input is classified and routed to a dedicated workflow instead of receiving a generic domain/homepage report. Email input returns MX routing, SPF policy evaluation, DMARC policy, CAA observations, a short common DKIM-selector check and the domain's public A/AAAA IP addresses. It also checks the email domain's own public HTTPS homepage for publicly published business contact emails, phone numbers, social links and visible profile-path identifiers. The deeper passive asset check adds certificate-transparency subdomains and resolves their public DNS IP addresses without scanning ports or probing services. Obvious markup/script fragments are filtered from heuristic location matches. These are domain-level published associations only; they do not establish that a mailbox owner controls any linked account. Website URL input returns URL structure indicators plus one read-only GET of that exact HTTPS URL after public-IP validation; redirects are not followed and forms are not submitted. Social-profile URLs are inspected at the exact supplied public profile path (not the platform homepage), with platform/slug metadata and optional focused search terms. Login walls, bot checks and privacy settings may limit results; private profiles, follower scraping, private contact discovery and cross-platform identity matching are out of scope. Bare domain input remains a domain-oriented DNS/profile lookup. Public DNS IP resolution is not a port scan and does not establish that a device is exposed or vulnerable. DNS-over-HTTPS now falls back from Cloudflare to Google if one resolver fails. Results explicitly identify unavailable checks instead of filling unrelated generic sections.

- **Phone Number Intelligence (menu option 16):** accepts an international-format phone number and reports the supplied digits, recognised country calling code, a broad numbering-region reference and digit count. This is offline parsing only; it does not identify a subscriber, carrier, registration date, last-used time, active status, linked IP/DNS or social accounts. Those details are not publicly derivable from a phone number and require lawful carrier/provider records or consent-based services. The built-in calling-code table is partial.
- **Scam investigation menu option 7:** accepts one explicitly supplied, owner-approved public HTTPS login page for read-only page/header/form inspection. No credentials are submitted and no authentication is attempted.
- **Malicious File & Link Analysis option 8 → 3:** runs automated URL investigation: public-host validation, DNS records, TLS certificate checks, one bounded HTTPS GET without redirects, and page metadata inspection. It does not execute browser code or download files. Set `GOOGLE_SAFE_BROWSING_API_KEY` locally to enable Google's threat-list lookup. Query parameter values and URL fragments are excluded from the saved report and reputation request.
- **Authentication log input:** the requested local file is an exported log from a website host, web server, reverse proxy, WAF or identity provider. Download/export it from a system the operator administers or is authorised to investigate, then provide its path on the Kali machine. CyberLab does not automatically access a website's private logs.
- **Hash inventory:** the existing option identifies likely hash formats in an authorised offline file only. It does not run John the Ripper or perform password guessing. CyberLab does not perform Hydra-style password spraying or dictionary attacks against live login pages; authorised login security can instead be reviewed through owner-provided logs, configuration and controlled staging assessments.


### Phone-number intelligence (menu option 16)

Option 16 always parses international numbering metadata. If the optional `phonenumbers` Python package is installed, it also reports possible/valid numbering-plan status, line type, approximate region description, international formatting and original number-range carrier assignment where available. Carrier data can be outdated after number portability. This does not identify a subscriber or reveal private registration dates, last-used timestamps, current activity, linked IP addresses, private social accounts or private fraud records.

Install the optional package in the Python environment used to run CyberLab if you want the extra numbering metadata:

```bash
python3 -m pip install phonenumbers
```

Use a virtual environment if Kali's system Python blocks global pip installation.

### Kali password-audit workflow

Install John the Ripper on Kali if needed:

```bash
sudo apt update
sudo apt install john
```

Kali commonly provides RockYou as a compressed wordlist. If it is present, decompress a working copy:

```bash
sudo gzip -dk /usr/share/wordlists/rockyou.txt.gz
```

Then use CyberLab menu option 14 → 8 or option 15 → 4. Supply a local hash file you are authorised to audit and the wordlist path (default: `/usr/share/wordlists/rockyou.txt`). This is the normal offline John workflow; no website is contacted.

For a website login page, use option 14 → 6 or option 15 → 3 and enter the authorised HTTPS URL. That is a read-only preflight, not an online Hydra password-guessing run. CyberLab intentionally does not automate Hydra dictionary attacks against live websites.


## Global Camera Intelligence (menu option 21)

The camera module adds three workflows without removing or renumbering existing CyberLab features:

- **Private LAN discovery:** checks common camera-related TCP ports on one explicitly supplied RFC1918 private IPv4 subnet containing at most 256 addresses. It requires the operator to confirm that they administer the network. Port matches are leads, not proof of camera identity or stream availability.
- **Authorised live camera viewing:** connects to one manually entered camera IP/hostname using its RTSP port and stream path. It supports both configured username/password authentication and cameras deliberately configured without authentication. The operator must confirm ownership or permission. The optional `ffplay` viewer is launched locally; RTSP URLs and credentials are not saved in reports. The URL is passed to ffplay, so local users with process-inspection privileges may be able to see it. Install it on Kali with `sudo apt install ffmpeg`.
- **Global public webcam directory:** provides links to services that intentionally publish webcams for public viewing (EarthCam, SkylineWebcams, Explore.org and Windy), where the operator can search by country or city.

The module does **not** search the public internet for exposed CCTV devices, enumerate unauthorised camera feeds, or connect to third-party cameras merely because they have no password. Publicly reachable does not mean consent to view. No camera credentials are guessed or bypassed.

Example installation for live viewing:

```bash
sudo apt update
sudo apt install -y ffmpeg
python3 kali-companion/cyberlab.py menu
```


## Phone number intelligence (menu option 16)

Option 16 performs local E.164 parsing and, when `phonenumbers` is installed, uses its bundled libphonenumber numbering-plan metadata to assess possible/valid format, number type, original carrier-range label and approximate numbering region. Install with `python -m pip install phonenumbers` in the active virtual environment. This is metadata enrichment, not a live subscriber lookup: it cannot reveal the subscriber's name, SIM registration date, last-used time, current carrier with certainty, private social accounts, fraud records or IP addresses. No SMS/call is sent and no phone number is submitted to a third-party lookup service. A valid numbering-plan result does not prove a number is active or assigned.


### Username OSINT (menu option 18)

Option 18 now performs three public-index searches for an operator-authorised username using the Brave Search API, deduplicates up to 25 returned pages, and saves source URLs, titles, snippets and available page-age metadata in the investigation report. It also retains the local username-format review. Search results are leads only: matching handles do not establish common ownership, and the tool does not access private profiles, login-protected pages, breach dumps or account-recovery flows.

Configure a Brave Search API key (the API requires a key; see https://api-dashboard.search.brave.com/documentation/guides/authentication):

```bash
export BRAVE_SEARCH_API_KEY='your-brave-search-api-key'
python3 kali-companion/cyberlab.py menu
```

Keep the key in your shell environment or a local untracked secrets file; never commit it to Git. Without the key, option 18 reports the setup requirement and does not pretend a search occurred.


### Automated password security audit (menu option 19)

Option 19 no longer asks the operator to self-report password controls. It automatically scans a selected local application source/configuration directory (or the current directory) for literal password/secret assignments, username-like configuration values and email addresses. Candidate literal secrets are redacted from the report. For up to 50 candidates, CyberLab checks breach-corpus exposure through the Have I Been Pwned Pwned Passwords range API using the k-anonymity method: only a five-character SHA-1 prefix is sent; the plaintext and full hash remain local. The report includes findings, severity, evidence counts, scan limits and remediation.

This is a static code/configuration audit, not a live account lookup. Email addresses and usernames are discovered locally but are not submitted to web search or breach services. No password is guessed, no login is attempted, and no full password or email address is sent to HIBP. Password reuse, MFA and reset-flow enforcement cannot be proven from source text alone; those require identity-provider configuration or authorised authentication logs.

Run option 19 and provide the path to your own application's source/configuration directory. Keep secrets out of source control; rotate any real secret found in a repository.


### Automated URL investigation

Menu option 8 → 3 performs a bounded investigation of an explicitly supplied public URL. It validates that the destination resolves to globally routable addresses, checks public DNS records, validates the HTTPS certificate, and makes at most one GET to the query-free URL path without following redirects. The response is parsed as inert text; JavaScript is not executed, forms are not submitted and files are not downloaded. HTTP URLs receive structural/DNS checks but are not fetched.

The target connection originates from the Kali machine and can be visible to the website operator. This is **not** an isolated sandbox or browser detonation environment. For a reputation lookup, configure a Google Safe Browsing API key in the local shell:

```bash
export GOOGLE_SAFE_BROWSING_API_KEY='your-google-safe-browsing-api-key'
python3 kali-companion/cyberlab.py menu
```

Keep API keys out of Git. The query-free URL path is sent to Google only when the key is configured; query values and fragments are intentionally removed because they may contain session tokens or private identifiers. A no-match result is not proof that a URL is safe.


### John the Ripper offline hash audit (Scam Investigation → option 4)

This operation accepts an **existing local hash-inventory file**, not a website name, domain or URL. CyberLab checks that both the hash inventory and wordlist exist as regular local files, are non-empty and within size limits, and that the inventory contains recognised hash-like records before it asks for authorisation or starts John. Missing files and ordinary text are rejected with an explicit message that no command was executed. The confirmation accepts `yes` or `YES`.

On Kali, the packaged RockYou list is often compressed. If `/usr/share/wordlists/rockyou.txt` is missing but `rockyou.txt.gz` exists, decompress a local copy with:

```bash
sudo gzip -dk /usr/share/wordlists/rockyou.txt.gz
```

Only after John and its result-summary command both complete successfully does CyberLab report `execution_status: completed` and `command_executed: true`. If validation, execution or result verification fails, no successful audit result is returned. Plaintext recovered values are discarded; only aggregate counts are retained. Use this workflow only for hash inventories you own or are explicitly authorised to audit.

## Per-user VPS gateway, device pairing and file hub (options 9-10)

CyberLab's remote-device architecture is **self-hosted per operator**. Each CyberLab user provisions and pays for their own VPS; CyberLab does not route users through a shared developer-owned server. The operator configures their own HTTPS gateway in option 9. Option 10 reads that gateway's real authenticated device registry; it must never display synthetic devices or simulated online states.

### Intended deployment model

- A lightweight gateway runs on the operator's VPS and owns that operator's device registry and file storage.
- Kali and enrolled companion devices initiate outbound, authenticated TLS connections to the operator's gateway. Do not expose remote device-management ports to the public internet.
- Pairing uses short-lived, single-use invitations, explicit device approval, per-device credentials and revocation.
- Device status is derived from authenticated heartbeats and server-side timestamps, not guessed from stale records.
- Gateway credentials and device secrets are stored locally with restrictive file permissions and are never committed to Git.

### Consent and session lifecycle

Remote capture is opt-in and permission-scoped. An invitation must disclose the requesting operator, the requested capabilities, the purpose, and the expected data destination before the recipient accepts. Camera, microphone, screen capture and location permissions are requested separately through the operating system or browser. Capture must remain visibly indicated while active. The recipient can stop sharing or revoke permissions at any time; the Kali operator can also stop the session. Revocation, loss of required OS/browser permission, or companion shutdown immediately stops capture and upload. CyberLab must not hide capture, bypass protected/restricted screens, or continue recording after the participant withdraws consent.

### File Hub

Files uploaded by an enrolled device are stored in that operator's own VPS storage namespace. The gateway may issue authenticated, expiring preview/download links for supported images, audio, video and documents. Links must not expose public directory listings or permanent unauthenticated access. Apply upload size/type limits, per-device authorization, retention controls, deletion, and audit events. The original file should remain downloadable; previews are an additional way to view it, not a replacement for the file.

### Gateway API implementation status

The first backend foundation is now present in `vps_gateway/app.py`:
- Health endpoint for option 9 connection checks.
- Owner-authenticated, expiring one-time pairing-code creation.
- Recipient-facing `/consent` webpage with separate camera, microphone, screen-share, one-time location and file-upload choices; browser/OS permission prompts are triggered only after the recipient clicks Grant. The page shows a local media preview, keeps the device token in page memory, sends heartbeats while open, and provides a Stop button. Closing the page stops local media tracks and attempts to revoke the device session. Pairing acceptance requires terms and explicit permission flags; device credentials are returned once and stored hashed.
- Authenticated device heartbeat and real device registry with online/offline status based on heartbeat age.
- Owner-controlled device revocation.
- Authenticated file upload/listing, per-device file namespace, and expiring share-token preview/download links.
- 25 MB upload limit and SQLite registry suitable for a small single-user VPS.

Option 9 in the Kali menu can save an HTTPS gateway URL and owner token with local file permissions 0600, test the health endpoint, and generate pairing codes. Option 10 reads the real registry and offers device revocation. The gateway installer creates a dedicated service account and systemd service bound to localhost only.

### Not implemented yet

The browser/companion recipient experience, companion-side permission prompts, native camera/microphone/screen/location capture, real-time media streaming, recipient-initiated session stop endpoint, file deletion/retention UI, and end-to-end integration tests are not yet implemented. The pairing accept API is a backend endpoint, not a finished user-facing consent page. Do not treat pairing as completed until a compatible companion exists. Do not report a successful camera/microphone recording, stream, location fix or screenshot unless a real permitted capture has occurred and been verified.

The service must be placed behind a properly configured HTTPS reverse proxy. Never expose its localhost port 8000 directly to the internet. Do not use plain HTTP for owner credentials or device tokens.
