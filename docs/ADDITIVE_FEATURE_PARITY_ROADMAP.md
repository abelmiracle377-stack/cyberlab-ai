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

## Blockchain engineering and Solidity security workstream

This workstream begins after the hosted AI gateway foundation. Delivery is incremental and additive; no wallet or chain action is enabled by the initial source-review slice.

### Solidity delivery sequence
1. **Source intake and static review (first slice):** bounded Solidity source input, contract/interface/library/import inventory, compiler pragma visibility and deterministic pattern-based review leads with line references.
2. **Compiler and project validation:** optional isolated compiler integration with pinned solc versions, reproducible project manifests, import resolution and no deployment by default.
3. **Deeper security analysis:** Slither and other reviewed static-analysis integrations, AST-aware checks, test generation, fuzzing and symbolic analysis in isolated environments.
4. **Smart-contract engineering:** project scaffolding, contract templates, test harnesses, deployment simulation and verified build artefacts.
5. **Chain-aware review:** EVM target selection, compiler/EVM compatibility, proxy/storage-layout analysis and chain-specific source provenance.
6. **Human-approved transaction workflows:** only later, with explicit chain/network, contract address, simulation, gas/fee preview and separate approval; never request private keys or seed phrases in chat.

The first Solidity source-review module is a heuristic aid, not a compiler, auditor, exploitability verdict or formal verification system. Wallet security and recovery are separate later workstreams and must not be conflated with contract analysis.

### Expanded Web3 engineering scope (user-directed)

The Solidity Lab is intended to grow into a full Web3 engineering workspace. These are planned capabilities, not claims that they are already implemented:

1. **Multi-language smart-contract authoring:** accept natural-language instructions and generate, explain, refactor and test Solidity first, then add other supported contract languages such as Vyper and Move where toolchains and target ecosystems are verified. Let the user specify language, compiler version, target chain/VM, standards, dependencies and project structure. Generated code must be clearly labelled as AI-authored and unverified until compiled and tested.
2. **Project build and test:** reproducible project scaffolding, pinned compiler/tool versions, dependency lockfiles, import resolution, unit/integration tests, static analysis, fuzz/property testing, gas snapshots and build artefacts. Support established toolchains through isolated, resource-bounded workers rather than assuming compilers exist in the hosted web process.
3. **NFT engineering:** ERC-721/ERC-1155 and chain-specific equivalents; metadata and media validation; minting/burning/royalty/access-control patterns; allowlists, reveal and supply controls; marketplace integration and testnets. Include metadata permanence, storage availability, royalty-enforcement limitations and marketplace compatibility in generated project notes.
4. **DEX engineering:** AMM and order-book design where appropriate; pools, swaps, liquidity provision/removal, routing, fee accounting, oracle integration, slippage/deadline protections, MEV and sandwich-risk analysis, flash-loan and reentrancy review, invariant/property tests, simulations and testnet deployment. Do not present a generated DEX as audited or production-safe.
5. **Deployment and wallet connection:** support user-selected networks and compatible wallets through standard wallet-provider interfaces. Before any transaction, show chain/network, account, contract address, constructor arguments, bytecode/build verification, transaction calldata, estimated gas limit, fee/gas price, native-token total, simulation result and any approvals. The user signs and submits in their own wallet; the app never asks for or handles a seed phrase or raw private key. Require a fresh explicit confirmation for every deployment, approval or value transfer. Provide testnet-first defaults, chain-ID checks, simulation, cancellation/error handling and transaction receipt tracking. A user-paid gas fee is paid by the wallet on the selected network; estimates can change before inclusion.
6. **Contract operations:** verify published source/bytecode where supported, inspect events and transactions, compare deployed bytecode, monitor configured contracts and create post-deployment reports. Any automated action remains separately permissioned and bounded.

### Wallet security and recovery workstream (after Web3 engineering)

**This is an active recovery-engineering workstream, not a guidance-only feature.** CyberLab AI's coordinator should be able to select, configure and run approved recovery utilities through the Kali companion or CyberLab OS sandbox, collect structured results, and help the user validate recovered access. It must not simply tell the user to go elsewhere and run a tool manually when the supported operation can safely be executed in CyberLab.

#### Recovery capabilities
- **Bitcoin and other wallet recovery:** integrate maintained, reviewed tools such as BTCRecover where their supported wallet formats and recovery modes match the user's backup. Add format adapters for supported Bitcoin Core, Electrum, hardware-wallet backup and other documented formats as validation establishes compatibility; do not claim universal wallet support.
- **Password/passphrase recovery:** run user-authorised candidate-based and typo-tolerant recovery against a supplied wallet backup, encrypted keystore or user-provided recovery material. Support bounded masks, known fragments and user-supplied candidate lists. Allow the user to configure time, memory, CPU/GPU and attempt budgets, and stop/cancel immediately.
- **Wallet discovery and validation:** identify backup/keystore formats, inspect non-secret metadata, test known derivation paths and account discovery, derive public addresses in the isolated worker, and compare them with addresses supplied by the owner. Validate a recovered wallet by deriving expected public addresses or checking a signed challenge; never ask the user to reveal the seed phrase in chat.
- **Other ecosystems:** add tool adapters only after format-specific support, tool licensing, test fixtures and security review. Prioritise Bitcoin first, then Ethereum-compatible keystores and other requested ecosystems according to verified tooling.
- **Outcome reporting:** report the exact backup format, tool/version, recovery mode, constraints, elapsed time, whether a candidate was recovered, validation evidence and limitations. Never fabricate a recovered secret or report success merely because a tool exited with code zero.

#### Sandbox and secret-handling architecture
- Run recovery tools in an isolated, disposable worker/container with a read-only input mount, encrypted ephemeral scratch storage, no inbound network, and outbound network disabled by default. Apply CPU, memory, disk, process, wall-clock and output-size limits. Destroy ephemeral scratch material after the user exports the result or the job expires.
- The AI coordinator may plan jobs and inspect redacted status/results, but must not receive raw seed phrases, private keys, keystore passwords or recovered secrets in model prompts, tool traces, telemetry, logs, analytics or hosted inference requests.
- Secret-bearing input is transferred directly from the user's local client or an explicitly trusted encrypted upload channel to the recovery worker, never through model context. Prefer local CyberLab OS execution when available; hosted recovery workers must require an explicit opt-in and disclose where encrypted data is processed.
- Provide a secret-safe result handoff: deliver recovered material directly to a user-controlled local vault/download channel protected by encryption and user authentication, never echo it into chat. Let the user verify and move funds using their own wallet software.
- Do not retain seed phrases, candidate passwords, recovered keys or plaintext wallet files. Redact command arguments and process output before audit logging. Record job metadata, tool version, timestamps, input hashes and outcome—not secrets.
- Use a strict tool registry with fixed executable paths, typed arguments, allowlisted operations, signed/pinned tool versions and per-tool permission tiers. No unrestricted shell, arbitrary downloads, or model-generated command execution.
- Require an ownership/authorisation declaration, explicit selection of the target backup and recovery scope, and a separate confirmation before starting expensive or long-running recovery. Show estimated resource use and let the user cancel.
- Keep recovery operations offline unless the user explicitly enables a separately justified public-chain lookup. Never broadcast transactions, move funds or sign on the user's behalf as part of recovery.

#### Safety and honest limits
- Support only wallets and backups the user owns or is explicitly authorised to recover. Refuse recovery attempts against third-party targets, stolen files or arbitrary addresses.
- This is not a promise to crack a wallet without adequate information. If the secret material is irretrievably lost and no useful backup, password clues or recoverable entropy remains, software cannot recreate it.
- A connected wallet exposes public account information and requests signatures/transactions through the wallet's own approval UI. CyberLab must not silently sign, export keys or bypass wallet protections.
- Include scam/phishing detection, malicious approval review, revoke-approval guidance, address poisoning warnings and transaction simulation where the chain/tooling supports it.
- The user must explicitly export any recovered secret into their own wallet. Never automatically sweep, transfer or consolidate recovered funds.

### File and digital-evidence recovery workstream (after wallet recovery)

- Build a dedicated recovery and forensics workflow for user-owned or explicitly authorised media: disk/image intake, filesystem and partition identification, deleted-file carving where supported, metadata/timeline analysis, hash manifests and recoverability estimates.
- Preserve originals: read-only acquisition, verified working copies, SHA-256 hashes, chain-of-custody events, timestamps and examiner notes.
- Run parsers and carving tools in isolated, resource-limited workers; never execute recovered files automatically. Flag encrypted, overwritten, damaged and unsupported data rather than promising recovery.
- Support exports and evidence reports with source image, tool/version, parameters, hashes, findings and limitations. Do not overwrite source media or write recovered output back to the source device.

### Delivery order override

The user has explicitly set the next product sequence: **(1) complete Solidity and Web3 engineering, (2) wallet security/recovery, (3) file and digital forensics/recovery, (4) full UI/UX design and integration, then (5) continue the remaining original CyberLab scope. CyberLab OS is deferred until those original CyberLab workstreams have been reached.** This ordering supersedes any earlier roadmap placement of CyberLab OS as an immediate next phase. Preserve its architecture notes and existing work; do not delete or disable it.

## CyberLab OS — first-class platform workstream

CyberLab OS is now a core product workstream, not a separate side project. It is the unified operating environment and local runtime management layer for CyberLab AI. It must preserve all existing web, agent, evidence, model and Kali companion functionality.

The detailed architecture and acceptance criteria are maintained in [docs/CYBERLAB_OS_ARCHITECTURE.md](./CYBERLAB_OS_ARCHITECTURE.md).

### CyberLab OS capabilities and delivery
- OS control plane integrated into the existing CyberLab AI dashboard, with a dedicated additive `/os` workspace.
- Read-only host and runtime capability discovery; report operating system, architecture, CPU, memory/disk headroom, hardware virtualisation and installed container/hypervisor runtimes.
- Environment inventory and lifecycle status with explicit available/configured/running/unsupported/planned states.
- CyberLab Terminal with a paired local runtime, bounded command execution, allowlists, audit trail and human approval for privileged, destructive or network-active actions. Never expose an unrestricted public shell.
- First-class integration with the existing Kali companion, pairing token, Nmap workflow, telemetry and Ollama adapter; preserve existing endpoints and behaviour.
- Optional Ubuntu, Kali-compatible and CyberLab Minimal/Security profiles using upstream images and package sources.
- Container environments before VM management where host support permits; explicit resource previews, filesystem/network isolation and confirmation for lifecycle changes.
- Local VM integration with QEMU/KVM, VirtualBox, VMware or Hyper-V only when detected and supported. Never attempt to run a hypervisor in the hosted web application.
- Future reproducible and signed bootable CyberLab OS image based on a maintained upstream Linux distribution. A custom kernel is not an initial requirement.
- Verify upstream distribution licensing, trademarks, image terms, package provenance, update and rollback strategy before redistributing images.

### CyberLab OS compatibility invariants
- Existing CyberLab AI pages, APIs, tools, Kali bridge routes, pairing and Ollama features remain available.
- Capability discovery is read-only; no package installation, container creation or VM lifecycle operation during discovery.
- No automatic scans, exploits, privileged commands, host mounts or network-enabled lab actions.
- Low-resource hosts receive lightweight environment recommendations; full desktop VMs are never assumed to be viable.
- Environment actions require explicit user initiation, clear scope/resource preview and approval where risk warrants it.
- The OS workspace remains useful when no container runtime or hypervisor is installed.

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
