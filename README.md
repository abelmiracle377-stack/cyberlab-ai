# CyberLab AI

An open-source AI-assisted cybersecurity research workspace for passive OSINT, IP intelligence, authorised assessment planning, vulnerability research, safe malware triage, binary inspection, network evidence analysis and Kali Linux workflows.

## Current status

The dashboard and AI agent are implemented. Available workspaces include passive IP intelligence, domain registration and certificate-transparency research, NIST NVD CVE search, Nmap XML report parsing, static malware triage, PE/ELF/Mach-O header inspection, authorised assessment scope planning, local Markdown report export, and an offline Kali companion.

Persistent project/evidence storage, richer binary analysis and authenticated website synchronisation for the offline companion are future work. The companion intentionally does not expose a remote shell or run active scans.

## Run locally

Requirements: Node.js 20.9+ and npm.

```bash
npm install
cp .env.example .env.local
npm run dev
```

Open http://localhost:3000.

For AI Gateway access, add `AI_GATEWAY_API_KEY` to `.env.local` only if Vercel OIDC is not available in your runtime. Never commit secrets or place keys in browser code. On Vercel, use Project Settings → Environment Variables, mark credentials Sensitive, and scope them only to required environments.

## Implemented features

- Responsive security research dashboard and streaming AI agent
- Dynamic model catalogue via Vercel AI Gateway
- Passive public IP intelligence, ASN/ISP context and reverse DNS
- Passive DNS resolution for A, AAAA, MX, NS and TXT records
- Public domain RDAP metadata and certificate-transparency research
- Public NIST NVD CVE search and CVSS summaries
- Nmap XML import with host, port and service summaries (parsing only)
- Static malware triage: SHA-256, file signature, entropy and selected string indicators (no execution)
- PE, ELF and Mach-O header inspection (no execution or disassembly)
- Authorised assessment scope planner with exclusions and pre-engagement checklist
- Local Markdown security report builder (no server-side storage)
- Offline Kali companion for static file triage and Nmap XML parsing
- Baseline HTTP security headers and secret-file exclusions

## Test

Run the offline companion tests with Python's standard library:

```bash
python -m unittest discover -s kali-companion -p "test_*.py" -v
```

The GitHub Actions workflow runs those tests and builds the Next.js application on pushes and pull requests to `main`.

## Kali companion

```bash
python3 kali-companion/cyberlab.py --help
python3 kali-companion/cyberlab.py triage ./sample.bin
python3 kali-companion/cyberlab.py nmap-xml ./authorised-scan.xml
```

No pip packages or API keys are required. See [kali-companion/README.md](./kali-companion/README.md).

## Security principles

- Use assessment features only on systems you own or are explicitly authorised to test.
- Active or potentially disruptive actions require explicit scope and human approval.
- The Kali companion does not expose an unauthenticated public shell, run scans, exploit hosts or execute samples.
- Findings should retain source, timestamp, context and confidence.
- IP geolocation and registration data are approximate network context, not proof of a private person's identity or exact location.
- Deceptive tracking, covert camera capture, private subscriber lookups and private browsing-history collection are out of scope.

## License

MIT. See [LICENSE](./LICENSE).
