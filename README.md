# CyberLab AI

An open-source AI-assisted cybersecurity research workspace for passive OSINT, IP intelligence, authorised assessment planning, vulnerability research, safe malware triage, binary inspection, network evidence analysis and Kali Linux workflows.

## Product roadmap

The additive capability-parity plan and Kodachi-inspired information architecture are documented in [docs/ADDITIVE_FEATURE_PARITY_ROADMAP.md](./docs/ADDITIVE_FEATURE_PARITY_ROADMAP.md). This plan preserves all existing routes, tools and workflows; planned capabilities are not represented as implemented until verified.

## Current status

The application includes an AI agent interface, passive IP and DNS intelligence, domain registration and certificate-transparency research, NIST NVD CVE search, Nmap XML report parsing, static malware triage, PE/ELF/Mach-O header inspection, authorised assessment scope planning, local Markdown report export, and an offline Kali companion. Not every navigation item represents a completed operational integration; use the dedicated tool pages and their returned status/errors to determine availability.

The encrypted evidence vault is browser-local and passphrase protected. Supabase email/password authentication and route protection are implemented as an optional deployment integration; they remain inactive until Supabase environment variables are configured. Central multi-user project storage and authenticated website synchronisation for the offline companion remain future work. The companion intentionally does not expose a remote shell or run active scans.

## Run locally

Requirements: Node.js 20.9+ and npm.

```bash
npm install
cp .env.example .env.local
npm run dev
```

Open http://localhost:3000.

For Supabase authentication, create a Supabase project and add `NEXT_PUBLIC_SUPABASE_URL` and `NEXT_PUBLIC_SUPABASE_ANON_KEY` to `.env.local` and Vercel Project Settings → Environment Variables. Configure the Supabase Auth Site URL and redirect URL as `https://cyberlab-ai.vercel.app/auth/callback` (and your local callback for development). Once both variables are present, `proxy.ts` protects workspace pages and API routes, and `/login` supports email/password sign-in and account creation. Use Supabase Row Level Security for any future user-owned database tables. Do not use a service-role key in the browser.\n\nFor AI access, create an OpenRouter API key and add `OPENROUTER_API_KEY` to `.env.local` or Vercel Project Settings → Environment Variables. Never commit secrets or place keys in browser code. Open-weight mode filters the OpenRouter catalogue for models with tool support and likely open-weight provenance; this classification is best-effort, does not guarantee a model is refusal-free, and does not remove CyberLab safety controls.

## Implemented features

- Live capability registry at `/tool-registry` and `/api/tool-registry`, with explicit operational/configured/partial/setup/planned states
- Specialist routing in the AI Agent for reconnaissance, vulnerability intelligence, malware triage, reverse engineering, blue-team analysis, reporting and general research; this is a first orchestration layer, not yet independent parallel agents
- Authenticated read-only MCP JSON-RPC endpoint at `/api/mcp` with `initialize`, `tools/list`, `tools/call`, and passive IP, DNS and NVD tools; disabled until `CYBERLAB_MCP_API_KEY` is configured

- Responsive security research dashboard and streaming AI agent
- Dynamic model catalogue via OpenRouter
- Open-weight research mode filters OpenRouter models by open-weight provenance heuristics and tool support, with deeper technical response style; safety boundaries remain enabled
- Public NVD CVE research with source references; live web search is not currently integrated
- Passive public IP intelligence, ASN/ISP context and reverse DNS
- Passive DNS resolution for A, AAAA, MX, NS and TXT records
- Public domain RDAP metadata and certificate-transparency research
- Public NIST NVD CVE search and CVSS summaries
- Nmap XML import with host, port and service summaries (parsing only)
- Static malware triage: SHA-256, file signature, entropy and selected string indicators (no execution)
- PE, ELF and Mach-O header inspection (no execution or disassembly)
- Authorised assessment scope planner with exclusions and pre-engagement checklist
- Local Markdown security report builder (no server-side storage)
- Browser-local evidence vault using AES-256-GCM and PBKDF2-SHA-256, with encrypted backup import/export
- Offline Kali companion for static file triage and Nmap XML parsing
- Baseline HTTP security headers and secret-file exclusions

## Test

Run the offline companion tests with Python's standard library:

```bash
python -m unittest discover -s kali-companion -p "test_*.py" -v
```

The GitHub Actions workflow runs those tests and builds the Next.js application on pushes and pull requests to `main`.


### Domain and privacy verification

- `/verification` adds passive domain mail/DNS posture checks: SPF, DMARC, common DKIM selectors, MX and CAA.
- Historical URL discovery queries the Internet Archive CDX API for public captures under a validated domain. Archived URLs are not proof of current availability or safety.
- Browser fingerprint transparency reads browser-exposed attributes locally in the browser; it does not submit them to CyberLab's server.
- This first verification slice does not claim to perform a full DNS leak test, WebRTC STUN test, TLS fingerprint test, global DNS propagation test, or anonymity verification. Those require dedicated controlled infrastructure and explicit privacy handling.

## Kali companion

The Kali companion now includes passive domain OSINT (RDAP, certificate transparency and DNS), public IP RDAP context, NIST NVD CVE search, static file triage and existing Nmap XML parsing. It uses Python's standard library and requires no pip packages or API keys.

```bash
git clone https://github.com/abelmiracle377-stack/cyberlab-ai.git
cd cyberlab-ai
python3 kali-companion/cyberlab.py doctor
python3 kali-companion/cyberlab.py --help
python3 kali-companion/cyberlab.py domain example.com
python3 kali-companion/cyberlab.py cve "OpenSSH"
```

See [kali-companion/README.md](./kali-companion/README.md) for all commands, data sources and limitations.

## Security principles

- Use assessment features only on systems you own or are explicitly authorised to test.
- Active or potentially disruptive actions require explicit scope and human approval.
- The Kali companion does not expose an unauthenticated public shell, run scans, exploit hosts or execute samples.
- Findings should retain source, timestamp, context and confidence.
- IP geolocation and registration data are approximate network context, not proof of a private person's identity or exact location.
- Deceptive tracking, covert camera capture, private subscriber lookups and private browsing-history collection are out of scope.

## License

MIT. See [LICENSE](./LICENSE).


## Live research and authorised active checks

- **Live Research** uses the existing `OPENROUTER_API_KEY` with Perplexity Sonar through OpenRouter to search current public web sources and return citations. Search requests may incur OpenRouter/provider charges.
- **AI Agent** can call the live research tool as part of a response. Confirm important claims against primary vendor, maintainer, NIST or CISA sources.
- **Active Security Lab** performs a deliberately limited TCP connection check against a public IPv4 address or domain after the operator confirms the exact target, provides an authorisation reference and retypes the target. It permits up to five selected common TCP ports and blocks private, loopback, link-local and reserved IPv4 ranges.
- The hosted TCP check is not Nmap, a full port scan, service fingerprinting, a vulnerability scan or proof of exploitability. Use the Kali companion locally for a fuller assessment within a verified written scope.
- Never test assets without explicit permission. Respect third-party/cloud-provider rules, engagement windows, exclusions and stop conditions.


### Local SOC host telemetry

The paired Kali companion exposes an authenticated `GET /system` endpoint for an on-demand, read-only host health snapshot. The Kali Connection workspace displays platform/release, uptime, load average, available memory, root-disk capacity, process count and Nmap availability. It does not collect usernames, process names, command lines, file contents, network payloads or authentication logs. It is not a continuous SIEM, EDR, intrusion-detection or ATT&CK event pipeline. The bridge remains bound to `127.0.0.1`, requires the existing pairing token and official-site origin, and must run on the same machine as the browser using it.
