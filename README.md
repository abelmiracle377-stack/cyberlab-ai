# CyberLab AI

An open-source AI-assisted cybersecurity research workspace for OSINT, IP intelligence, authorised security assessment, vulnerability research, malware triage, reverse engineering and Kali Linux workflows.

## Current status

The dashboard and AI research agent console are implemented. The agent uses the Vercel AI SDK with Vercel AI Gateway and currently exposes passive IP intelligence and DNS resolution tools. Persistent project storage, CVE intelligence, scan-result imports, advanced malware analysis and the Kali companion remain planned work.

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
- Server-side credential handling and request validation

## Roadmap

- Evidence and project persistence
- CVE and vulnerability intelligence
- Authorised Nmap result import and analysis
- Safe static malware triage and reverse engineering
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

No license has been selected yet. Choose a license before inviting external contributions or distributing the project for reuse.