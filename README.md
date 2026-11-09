# CyberLab AI

An open-source AI-assisted cybersecurity research workspace for passive OSINT, IP intelligence, authorised assessment planning, vulnerability research, safe malware triage, binary inspection, network evidence analysis and Kali Linux workflows.

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

For Supabase authentication, create a Supabase project and add `NEXT_PUBLIC_SUPABASE_URL` and `NEXT_PUBLIC_SUPABASE_ANON_KEY` to `.env.local` and Vercel Project Settings → Environment Variables. Configure the Supabase Auth Site URL and redirect URL as `https://cyberlab-ai.vercel.app/auth/callback` (and your local callback for development). Once both variables are present, `proxy.ts` protects workspace pages and API routes, and `/login` supports email/password sign-in and account creation. Use Supabase Row Level Security for any future user-owned database tables. Do not use a service-role key in the browser.\n\nFor AI Gateway access, add `AI_GATEWAY_API_KEY` to `.env.local` only if Vercel OIDC is not available in your runtime. Open-weight mode uses models available through the configured AI Gateway catalogue; it does not guarantee a model is refusal-free or remove CyberLab safety controls. Never commit secrets or place keys in browser code. On Vercel, use Project Settings → Environment Variables, mark credentials Sensitive, and scope them only to required environments.

## Implemented features

- Responsive security research dashboard and streaming AI agent
- Dynamic model catalogue via Vercel AI Gateway
- Open-weight research mode filters on Gateway `open-weights` and `tool-use` tags, with deeper technical response style; safety boundaries remain enabled
- Public web research through AI Gateway search, with source links for current advisories and technical references
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
- Offline Kali companion for passive OSINT, static file triage, Nmap XML parsing and defensive password/authentication auditing
- Baseline HTTP security headers and secret-file exclusions

## Test

Run the offline companion tests with Python's standard library:

```bash
python -m unittest discover -s kali-companion -p "test_*.py" -v
```

The GitHub Actions workflow runs those tests and builds the Next.js application on pushes and pull requests to `main`.

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


### Password & Authentication Security

The Kali companion includes a defensive password and authentication menu (option 14): local password-strength review with hidden input, strong password generation for new/reset credentials, labelled usernames for owned lab test accounts, password-storage metadata review, authentication-control checklist and local authentication-log analysis. It does not generate password guesses for existing accounts, crack hashes, enumerate real users or attempt logins. See [kali-companion/README.md](./kali-companion/README.md).
