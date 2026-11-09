# CyberLab AI Kali Companion

A command-line research companion for Kali Linux and other Linux distributions. It adds passive OSINT and public vulnerability intelligence to the original local evidence tools. Python 3.9+; Python standard library only; no pip packages or API keys. Optional `figlet` and `chafa` packages provide the large coloured startup lettering and terminal mascot artwork.

## Install

```bash
git clone https://github.com/abelmiracle377-stack/cyberlab-ai.git
cd cyberlab-ai
sudo apt update && sudo apt install -y figlet chafa
python3 kali-companion/cyberlab.py doctor
python3 kali-companion/cyberlab.py menu
python3 kali-companion/cyberlab.py --help
```

## 14-option Kali command centre

Launch the full local-first menu:

```bash
python3 kali-companion/cyberlab.py menu
```

The menu exposes the six existing research tools, a guided Manual Security Assessment & Verification at option 3, static file and URL analysis, device connection status, connected-device status, live-session status, local evidence listing and investigation history. URL analysis is structural and does not visit or download the URL. File and image analysis uses static signature/hash/string triage; it does not execute files or guarantee a malware verdict.

Device pairing, remote connected-device listing and live capture controls are intentionally shown as not configured until the authenticated gateway and platform-specific companion applications exist. The CLI does not pretend those remote capabilities are already working.

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
- Local authentication-log pattern summaries (up to 5 MB), without network activity.

This is not John the Ripper or Hydra: it does not crack password hashes, generate target password dictionaries, enumerate real users, attempt logins, or send authentication traffic. Results are local review signals, not proof that a system is secure.


## Law Enforcement & Scam Investigation (menu option 15)

This is a public-source and evidence-review workspace, not an account-access tool. It provides:
- Public scam-site intelligence using RDAP, DNS, certificate-transparency records and the supplied domain's public homepage.
- One explicitly supplied HTTPS page inspection using a read-only GET; redirects are not followed and forms are never submitted.
- Offline authentication-log analysis to identify failed/successful login indicators and recurring source addresses. This is the defensive, Hydra-style side: detect and investigate authentication abuse from logs, not generate login attempts.
- Local password-hash inventory classification by format counts (Argon2, bcrypt, PBKDF2 and ambiguous hex lengths). This is the safe, John-style side: identify storage-format risks without cracking, wordlists or returning hash values.
- Locally saved evidence notes and investigation reports.

**Important boundary:** CyberLab does not run Hydra, John the Ripper, password spraying, brute-force attacks, credential stuffing, login bypass, hash cracking or password-dictionary generation. It cannot access scammer accounts or use discovered usernames to guess passwords. Use formal legal process and the relevant provider's preservation/disclosure channels for account records. Public indicators are leads, not attribution or proof of criminal activity.


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

- **Expanded DNS Intelligence (menu option 2):** accepts a public domain, website URL, email address or public social-profile URL. For domain/email inputs it combines existing DNS records with public A/AAAA resolution, public homepage metadata, publicly visible email/phone strings, social/community links (including Facebook, LinkedIn, Instagram, X, YouTube, TikTok, GitHub, Slack and Discord), basic organisation/location metadata, and passive CDN/rate-limit header observations. Social-profile URLs are recorded as references only. It does not scrape authenticated profiles, infer private identities, count connected users, scan ports, test DDoS resilience or generate traffic. Extracted company/address/location metadata is heuristic and should be verified independently.
