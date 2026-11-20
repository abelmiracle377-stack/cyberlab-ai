# CyberLab AI

An AI-assisted cybersecurity workspace that unifies OSINT and reconnaissance, authorized offensive testing, a full autonomous SOC, digital forensics and wallet recovery, and a hands-on security academy — with an offline Kali companion that executes real tools on your own machine.

CyberLab is for work you are authorized to do: systems you own, lab environments, and engagements with written permission. It is not a tool for attacking systems you don't control.

---

## What's inside

### AI agent & research
- Streaming AI agent with specialist routing (reconnaissance, vulnerability intelligence, malware triage, reverse engineering, blue-team analysis, reporting, general research).
- Dynamic model catalogue via OpenRouter, with an open-weight research mode (filters for tool-capable, likely open-weight models; safety controls remain on).
- **Live Research** via Perplexity Sonar through OpenRouter, returning cited public sources.
- Optional operator-configured unfiltered model gateway (server-only env, per-user monthly token allowance) — see [docs/UNCENSORED_AI_GATEWAY.md](./docs/UNCENSORED_AI_GATEWAY.md).
- Authenticated read-only MCP JSON-RPC endpoint at `/api/mcp` (`initialize`, `tools/list`, `tools/call`; passive IP/DNS/NVD tools), disabled until `CYBERLAB_MCP_API_KEY` is set.

### OSINT & reconnaissance
- Passive public IP intelligence (ASN/ISP context, reverse DNS), passive DNS (A/AAAA/MX/NS/TXT), RDAP domain metadata and certificate-transparency research.
- NIST NVD CVE search with CVSS summaries and source references.
- Domain mail/DNS posture at `/verification`: SPF, DMARC, common DKIM selectors, MX, CAA, plus Internet Archive historical-URL discovery and local browser-fingerprint transparency.
- **Shodan OSINT** (companion): host lookup, index search, DNS resolve and account info over the official Shodan API with your own key — read-only, executed via the bridge (`/shodan/*`). UI at `/shodan`.

### Web application security
- **Web Application Assessment** (`/web-assessment`) — a bug-bounty baseline, detection-only within a confirmed authorized scope: security-header and cookie hardening, information disclosure, sensitive-file exposure (`.git`/`.env`/`server-status`), open-redirect, error-based SQL-injection and reflected-input detection, and risky HTTP methods — each mapped to OWASP/CWE with remediation.
- Native web workbench, crawler, repeater, active checks and a Burp/Montoya connector.

### Authorized Wi-Fi testing
A full engagement toolkit for networks you own or are authorized to test, executing the standard Kali tools on your own adapter via the bridge (`/wifi/*`). UI at `/wifi` and `/wifi-crack`.
- **Passive** (`wifi_assessment.py`): enumerate interfaces, inventory nearby networks from beacons, audit posture (open / WEP / WPA / WPA2 / WPA3) with remediation.
- **Active** (`wifi_authorized.py`, every operation gated behind an authorization confirmation + engagement reference): monitor-mode enable/disable, targeted bounded deauthentication, WPA 4-way-handshake capture, clientless PMKID capture, WPA dictionary cracking (aircrack-ng / hashcat), WPS PIN attacks (reaver Pixie-Dust / bully), and automated audits (wifite).
- **Offline WPA crack** (`/wifi-crack`): upload a capture; the companion writes it to a temp file, cracks it against a local wordlist, and deletes it — nothing is transmitted.

### CyberSOC — autonomous security operations
An AI-driven SOC with a restrained enterprise console — see [docs/CYBERSOC.md](./docs/CYBERSOC.md).
- Detection/triage engine with severity scoring and MITRE ATT&CK mapping; union-find **incident correlation**; threat-intel (IOC) matching; analyst-tunable alert **suppression**; an autonomous auto-response runner (safe actions auto-run, destructive ones escalate).
- **Case management** — group an incident's alerts into one investigation with a shared, consolidated timeline.
- **Splunk & Wazuh** connectors (companion), and an **external-exposure** feed that turns Shodan findings (risky exposed services, known CVEs) into correlated alerts, with saved assets and recurring sweeps.
- Console: KPI strip with MTTR, alerts + incidents + cases views, assignment, investigation notes, one-click rule muting.

### Digital forensics & wallet recovery
- Static malware triage (SHA-256, signature, entropy, string indicators — no execution), PE/ELF/Mach-O header inspection, Nmap XML parsing.
- Read-only forensic artifact parsing on the companion: Apple plists, SQLite databases (browser history/cookies/logins, opened read-only + immutable) and Windows registry hives.
- Local wallet recovery: BIP39 multi-coin derivation and account/change sweep, Electrum (v2 standard/segwit and old) seeds, partial/scrambled seed reconstruction, MetaMask vaults, BIP38 encrypted keys (incl. EC-multiply), and password cracking across the full hashcat/John attack range. Never paste private keys or seed phrases you don't own.

### CyberLab Academy
Hack The Box / TryHackMe-style learning — see [docs/ACADEMY.md](./docs/ACADEMY.md).
- Tracks: Web Application Security, SOC Analyst Fundamentals, Attack Techniques & Defense (XSS, SSH key security), and a **Capture The Flag** track with ten flags across three difficulty tiers against a bundled deliberately-vulnerable target (recon/disclosure, SQLi, IDOR, path traversal, cookie auth bypass, JWT `alg:none`, SSRF).
- Attack the CTF target either with real tools against the local companion lab, or entirely in the browser via a hosted target and an in-app **Attack Console**.
- Hands-on rooms, embedded videos, server-graded flag answers, per-challenge write-ups and walkthroughs that unlock after capture, a cross-user scoreboard, progress tracking, earnable certifications (CCWT, CCSA, CCCP, CCD), public verification at `/verify`, and a printable certificate at `/certificate/<serial>`.

### Community, evidence & cases
- Community chat: usernames, friend requests, direct messages with pictures and voice notes, **end-to-end encrypted** in the browser (ECDH P-256 + AES-GCM) so the server stores only ciphertext — see [docs/SOCIAL_CHAT.md](./docs/SOCIAL_CHAT.md).
- Browser-local evidence vault (AES-256-GCM + PBKDF2-SHA-256) with encrypted backup import/export.
- Persistent investigation cases at `/investigations` (owner-scoped under Supabase RLS) with timeline events and Markdown export; companion-side case export, local archival with SHA-256 manifests, and read-only integrity/audit-ledger verification.
- Authorized assessment scope planner, local Markdown report builder, live capability registry at `/tool-registry`.

### Solidity & blockchain
- `/solidity` reviews bounded Solidity source: contract/interface/library/import inventory plus line-referenced heuristic review leads (incl. NFT/DEX indicators). Optional local compile and constrained test-run via the companion. It does not deploy, connect wallets, sign transactions or touch a chain — see [docs/BLOCKCHAIN_ENGINEERING.md](./docs/BLOCKCHAIN_ENGINEERING.md).

### CyberLab OS
A Debian-based bootable workstation workstream under [os/](./os/), with read-only host-capability discovery through the companion (`GET /capabilities`). See [docs/CYBERLAB_OS_ARCHITECTURE.md](./docs/CYBERLAB_OS_ARCHITECTURE.md).

---

## Design system

CyberLab uses a tactile, dark-slate workspace rather than a neon sci-fi template, tuned for extreme readability and purposeful motion.

- **Palette** — Deep Obsidian `#0D1117` canvas, Dark Slate `#161B22` panels, Muted Steel `#30363D` borders, Off-White Ash `#E6EDF3` text, Cool Gray `#8B949E` metadata, with meaning-carrying accents: Phosphor Mint `#2EA043` (success/active), Electric Cyan `#58A6FF` (links/paths), Amber Gold `#D29922` (warnings), Signal Crimson `#F85149` (critical).
- **Typography** — JetBrains Mono for terminals, logs and data columns; Inter for interface and copy.
- **Motion** — a subtle animated binary-field background, plus reusable micro-animations (character-scramble reveals, typewriter log streaming, marching-ants connection paths, pulsing nodes, snappy ~180ms panel transitions). Motion is driven by actions and honors `prefers-reduced-motion`.

---

## Run locally

Requirements: Node.js 20.9+ and npm.

```bash
npm install
cp .env.example .env.local
npm run dev
```

Open http://localhost:3000.

### Environment variables
- `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY` — Supabase auth and data (set the Auth Site URL / redirect to `/auth/callback`). Without them, auth and persistence stay inactive.
- `OPENROUTER_API_KEY` — AI agent and Live Research.
- `SUPABASE_SERVICE_ROLE_KEY`, `PAYSTACK_SECRET_KEY`, `PAYSTACK_PLAN_CODE` — server-only, for admin and billing.
- `CYBERLAB_MCP_API_KEY`, `CYBERLAB_UNCENSORED_*` — optional, server-only.

Never commit secrets or put service-role/Paystack keys in browser code.

### Supabase migrations
Apply in order in the Supabase SQL Editor:

```
202611130001_investigation_cases        202611200003_cybersoc
202611130002_billing_and_admin          202611200004_cybersoc_notes
202611130003_admin_knowledge_base       202611200005_cybersoc_tuning
202611140001_ai_usage_gateway           202611200006_cybersoc_cases
202611140002_expand_ai_usage_reservations  202611200007_academy
202611150001_admin_ai_learning_control  202611200008_academy_verify
202611200001_social_chat                202611200009_academy_scoreboard
202611200002_social_chat_e2ee           202611200010_soc_exposure_assets
```

---

## Kali companion

The companion runs on your Kali/Linux machine, uses Python's standard library (no pip packages or API keys for its core), and exposes a loopback bridge bound to `127.0.0.1` with a machine-local pairing token. It executes the real tools (Nmap, aircrack-ng suite, hashcat, Shodan API, etc.) locally.

```bash
git clone https://github.com/abelmiracle377-stack/cyberlab-ai.git
cd cyberlab-ai
python3 kali-companion/cyberlab.py doctor
python3 kali-companion/cyberlab.py --help
python3 kali-companion/cyberlab.py domain example.com
python3 kali-companion/cyberlab.py cve "OpenSSH"
```

See [kali-companion/README.md](./kali-companion/README.md) for all commands, data sources and limitations.

**Authentication boundary:** the companion and bridge run independently on the Kali machine and don't require a CyberLab web account or subscription to run local commands. The bridge uses local pairing protection (token + `127.0.0.1` binding), not a web login. Hosted AI/API features remain subject to web-app authentication.

---

## Test

```bash
python -m unittest discover -s kali-companion -p "test_*.py" -v
```

The GitHub Actions workflow runs the companion tests, the TypeScript/Node unit tests, the Next.js build, and the Burp/Montoya checks on pushes and pull requests.

---

## Accounts & billing

Supabase Auth provides sign-up/login; the hosted workspace is USD $10/user/month via Paystack (plan in USD, amount 1000 minor units, monthly; webhook `…/api/paystack/webhook`). `/admin` (role `admin` only) manages roles and access; `/billing` handles checkout; `/pricing` is public. Promote the owner by setting `public.user_profiles.role='admin'` in Supabase. Test with Paystack test keys first.

---

## Security principles

- Use assessment and offensive features only on systems you own or are explicitly authorized (in writing) to test. Active operations require explicit scope and human approval; the Wi-Fi, web-assessment and crack tools enforce an authorization confirmation.
- The companion does not expose an unauthenticated public shell; it binds to `127.0.0.1` and requires its pairing token.
- CyberLab does not build deployable malware, worms, credential-theft payloads, or anti-bot/CAPTCHA bypass; the Academy teaches those techniques defensively instead.
- Findings retain source, timestamp, context and confidence. IP geolocation and registration data are approximate network context, not proof of identity or exact location.
- Deceptive tracking, covert capture, private-subscriber lookups and private browsing-history collection are out of scope.

## License

MIT. See [LICENSE](./LICENSE).
