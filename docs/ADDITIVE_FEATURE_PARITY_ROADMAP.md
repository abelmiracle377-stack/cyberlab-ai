# CyberLab AI — Additive Feature Parity and UX Roadmap

## Non-negotiable preservation rule

This programme is additive. Do not delete, rename, disable, or silently replace existing CyberLab AI pages, API routes, Kali companion commands, environment variables, or workflows. Extend current modules in place or add new routes. Keep old URLs working. Every phase must pass existing tests and production build before merge.

## Product direction

Build an integrated security research and operations workspace inspired by the capability breadth of HexStrike AI, the agent orchestration and guardrail research in CAI, and Kodachi's coherent cockpit, observability and public verification-tool organization. Reimplement compatible ideas in CyberLab's own architecture; do not copy branding, proprietary code, assets, or restricted CAI components.

Kodachi's public whitepaper describes three tiers: client/workstation services, managed infrastructure, and online verification services. CyberLab should adopt the organizational idea without claiming to be an anonymity OS or offering VPN infrastructure it does not operate.

## Capability catalogue

### A. AI orchestration and tool gateway (HexStrike / CAI-inspired)
- Central planner with task decomposition and specialist agents: recon, web, vulnerability intelligence, malware triage, reverse engineering, cloud/container, blue-team and reporting.
- MCP gateway with explicit tool discovery, schemas, timeouts, cancellation, structured outputs and audit events.
- Tool registry with capability metadata, install/health checks, version reporting and per-tool permission tiers.
- Sequential and parallel workflows, bounded retries, evidence handoffs, human approval gates and reproducible run histories.
- Input/output guardrails, prompt-injection isolation for fetched pages/files, tool-output provenance, secrets redaction and policy enforcement.
- Agent tracing, cost/latency tracking, evaluation datasets and regression tests.
- No generic unrestricted shell tool exposed to a hosted model. Local command execution must be fixed-command/allowlist based and user-approved.

### B. Reconnaissance and web application security (HexStrike-inspired)
- Nmap local Kali integration; bounded HTTPX probing; passive subdomain discovery; DNS/RDAP/CT/WHOIS; historical URL discovery; technology fingerprinting.
- URL crawling and endpoint inventory, robots/sitemap review, TLS/certificate inspection, HTTP security headers, cookie checks, CORS and security.txt review.
- Nuclei integration only with pinned, reviewed templates and explicit scope/rate limits; safe checks default.
- Directory/content discovery, parameter discovery and authenticated testing only with explicit scope and separately enabled profiles.
- Import/export of Nmap, SARIF, JSON, CSV and supported scanner reports.
- No automatic exploitation, credential attacks, destructive tests, stealth/evasion or internet-wide scanning.

### C. Vulnerability and threat intelligence
- NVD/CVE, CVSS, CISA KEV, vendor advisories, EPSS where licensed/available, package and container vulnerability context.
- IP/domain reputation, ASN, hosting, DNS, mail posture, certificate transparency, blacklist and threat-indicator lookups.
- Historical URL and public archive discovery, security news feed, source citations, timestamps, confidence and cache freshness.
- Correlate asset inventory to CVEs and remediation guidance; never infer vulnerability solely from a version banner.

### D. Malware and reverse engineering
- Existing upload triage plus direct HTTPS sample URL retrieval with SSRF controls, strict byte/time limits and no execution.
- Hashes (SHA-256 and optional BLAKE3), file type, entropy, strings, PE/ELF/Mach-O metadata, imports/exports and signature checks.
- YARA rules (reviewed and versioned), sandbox integration as an optional isolated service, reputation lookups and IOC extraction.
- Reverse-engineering integrations: Ghidra/radare2/objdump/readelf/strings and disassembly/decompilation where locally installed.
- Memory/disk/forensic artefact analysis only from explicitly supplied evidence and isolated tooling.
- Do not execute downloaded samples on the host or send private samples to third parties without explicit opt-in.

### E. Cloud, container, source and infrastructure security
- Trivy for images/filesystems, SBOM generation and dependency/license scanning.
- Prowler/ScoutSuite cloud posture checks through user-provided, least-privilege credentials; never collect cloud secrets in chat.
- Kubernetes configuration and benchmark checks; Docker configuration review.
- Repository secret scanning, static analysis, IaC review and CI configuration checks.

### F. Kodachi-inspired privacy verification and system cockpit
- Public IP / IPv4-IPv6 visibility, ASN/ISP context and network type.
- Browser WebRTC/DNS leak checks and browser fingerprint transparency; clearly explain limitations and collect no unnecessary identifying data.
- DNS leak/resolver checks and DNS propagation across resolvers.
- Domain intelligence covering A/AAAA/MX/NS/TXT, SPF/DKIM/DMARC, TLS, HTTP headers and exposure context.
- File hash and signed-manifest verification for CyberLab companion releases.
- Service health/status page with uptime, latency, incident notes and degraded-state messaging.
- Host telemetry and SOC dashboard with processes, connections, services, file integrity, authentication events and ATT&CK mapping; read-only monitoring by default.
- Privacy posture summary and security score with transparent component weights and unknown/not-applicable states.
- Do not claim anonymity, forensic resistance, VPN protection or endpoint compromise detection without independently verified implementation.

### G. Reporting and operations
- Central investigation/case workspace; asset inventory; scope, exclusions, approvals and stop conditions.
- Evidence vault, chain-of-custody metadata, signed exports, report templates, timeline and audit log.
- Notification center, scheduled jobs, recurring health checks and user-configurable thresholds.
- Searchable tool catalogue, command builder, workflow queue, output formats, job history and cancellation.
- System status, API docs, help center and guided remediation.

## Kodachi-inspired information architecture

Keep every existing route and page. Organize navigation into these additive sections:

1. **Command Center** — Overview, AI Agent, Cases, Activity, Notifications.
2. **Intelligence** — Domain, IP, DNS, OSINT, Historical URLs, Threat Intel, Live Research.
3. **Assessment** — Website Assessment, Recon, Network, Vulnerability, Penetration Testing, Scope Manager.
4. **Analysis** — Malware, Reverse Engineering, Forensics, Cloud & Container, Repository Security.
5. **Operations** — SOC, Host Monitor, Tool Registry, Workflows, Kali Connection, Service Status.
6. **Verification & Privacy** — IP/Network identity, DNS leak, WebRTC, Browser Fingerprint, DNS Propagation, File Integrity.
7. **Evidence & Governance** — Cases, Evidence Vault, Reports, Audit Log, Policies.
8. **System** — Settings, Providers, API docs, Help.

UX principles: dark, high-contrast operational cockpit; restrained green status accents and amber warnings; compact monospace metadata; searchable left navigation; clear current mode and target scope; issue-first status; data freshness and source provenance; responsive layout; no decorative false status indicators. Add cockpit views (Classic, SOC, Vitals) as presentation modes over the same capabilities, not separate implementations.

## Delivery phases

### Phase 0 — Baseline and architecture
- Inventory all existing routes, APIs, CLI commands, environment variables and tests.
- Create capability registry and feature-status vocabulary: implemented, partial, planned, unavailable.
- Add compatibility tests that protect existing routes and companion commands.
- Document threat model, data flows, permission tiers and privacy boundaries.

### Phase 1 — UX shell and service health
- Add Kodachi-inspired information architecture without removing existing navigation.
- Add global search, command palette, service/tool status, notifications and recent activity.
- Add responsive cockpit layouts and transparent status/freshness indicators.

### Phase 2 — Tool gateway and agent orchestration
- Add typed tool registry and safe MCP gateway.
- Connect existing local Kali Nmap bridge through explicit pairing and approvals.
- Add specialist agent handoffs, guardrails, traces, cancellation and run audit.
- Add tool health/version checks; keep tools unavailable until installed and tested.

### Phase 3 — Intelligence and verification
- Domain/IP intelligence, historical URL sources, DNS propagation, TLS/mail checks, privacy verifier, browser fingerprint and signed-file verification.
- Add source citations, freshness, caching and rate limits.

### Phase 4 — Security operations and assessment
- Expand recon and web assessment with scope-bound, low-impact defaults.
- Add reviewed Nuclei profiles, endpoint inventory and scanner report imports.
- Add SOC/host monitoring and service health.

### Phase 5 — Malware, reverse engineering and cloud
- Extend static triage, YARA, disassembly/decompilation, SBOM, Trivy and cloud posture integrations.
- Optional isolated sandbox, only with explicit opt-in and clear sample handling.

### Phase 6 — Workflow automation and validation
- Workflow builder, scheduling, notification thresholds, case management and evidence reports.
- Security review, dependency/license review, unit/integration tests, accessibility, performance and production deployment verification.

## Acceptance criteria for every feature

- It is an operational feature, not a decorative card or an "Import files" placeholder.
- It has a real input path, backend/tool integration, validation, meaningful output, error handling and tests.
- It clearly reports whether the required service/tool/API key is missing.
- It records source, time, scope and confidence where applicable.
- It respects explicit authorization and safe defaults.
- Existing CyberLab features, routes and commands continue to work.
- No feature is marked "Available" until verified end-to-end.
