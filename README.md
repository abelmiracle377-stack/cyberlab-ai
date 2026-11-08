# CyberLab AI

An open-source AI-assisted cybersecurity research workspace for OSINT, IP intelligence, authorised security assessment, vulnerability research, malware triage, reverse engineering and Kali Linux workflows.

## Current status

The dashboard, AI research agent, passive domain OSINT workspace, Nmap XML report analyser and static malware triage workspace are implemented. The agent exposes passive IP intelligence, reverse DNS, DNS resolution and public NVD CVE search. The network analyser parses user-supplied XML only; the malware module performs static inspection without executing or storing samples. Persistent project storage, advanced reverse engineering and the Kali companion remain planned work.

## Run locally

Requirements: Node.js 20.9+ and npm.

```bash
npm install
cp .env.example .env.local
npm run dev
```

Open http://localhost:3000.

For local AI inference, add an AI Gateway key to `.env.local` as `AI_GATEWAY_API_KEY`. Never commit this file or paste real keys into source files. It is ignored by Git. On Vercel, prefer Vercel OIDC for production authentication; otherwise add the key in Project Settings → Environment Variables, mark it Sensitive, and scope it only to required environments.

## Implemented

- Responsive security research dashboard
- Dynamic model catalogue from Vercel AI Gateway
- Server-side streaming AI agent
- Passive public IP intelligence lookup
- Passive DNS record resolution (A, AAAA, MX, NS, TXT)
- Reverse DNS (PTR) lookups
- Public NIST NVD CVE search and CVSS summaries\n- Nmap XML import with host, port and service summaries (report parsing only)\n- Static malware triage: SHA-256, file signature, entropy and selected string indicators (no execution)
- Server-side credential handling and request validation

## Roadmap

- Evidence and project persistence
- CVE and vulnerability intelligence
- Authorised Nmap result import and analysis
- Advanced reverse engineering workflows
- Report generation and export
- Authenticated Kali Linux companion with allowlisted tasks and explicit approvals

## Security principles

- Use assessment features only on systems you own or are explicitly authorised to test.
- Sensitive or potentially disruptive actions require clear scope and human approval.
- The Kali companion will not expose an unauthenticated public shell.
- Findings should retain source, timestamp, context and confidence.
- Network registration and geolocation data must not be presented as proof of a private person's identity.
- Deceptive tracking, covert camera capture, private subscriber lookups and private browsing-history collection are out of scope.

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE).