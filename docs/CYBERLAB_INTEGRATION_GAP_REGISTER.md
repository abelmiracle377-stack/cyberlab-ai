# CyberLab AI — Integration & Gap Register

**Audit date:** 2026-11-18  
**Repository:** `abelmiracle377-stack/cyberlab-ai`  
**Baseline:** `main` at `9664f0e7530bc8f929f39ba5c10feee6933b3db7`  
**Register branch:** `docs/integration-gap-register`  
**Purpose:** Single working register for branch consolidation, capability verification, security hardening, test coverage, and release readiness.

> This register records repository observations and planned verification. A documented or UI-visible feature is not considered complete until its implementation, API path, safety controls, tests, and end-to-end behaviour are verified. Do not infer production readiness from a successful build.

## 1. Branch inventory

The following seven branches were present during the audit:

| Branch | Workstream | Audit disposition |
|---|---|---|
| `main` | Platform baseline, dashboard, auth, billing, shared app | Protected integration baseline; do not replace |
| `feature/cyberlab-burp-integration` | Native web proxy/workbench, Burp connector, packet capture, Repeater, web testing | Highest-priority technical review and integration candidate |
| `feature/kali-command-centre` | Kali command centre, device gateway and tool workflows | Review open PR #1; verify each device action end-to-end |
| `feature/additive-forensics-recovery` | Forensics, imaging/recovery, OS build work | Review open PR #2; preserve additive scope |
| `feature/agent-multimodal-inputs` | Agent attachments, Ollama/OpenRouter and multimodal inputs | Integrate after API contract and auth review |
| `feat/model-intelligence-workspace` | Model intelligence, planning and specialist workflows | Reconcile with agent branch; avoid duplicate orchestration |
| `milestone/nmap-evidence-parity` | Nmap jobs, scan parsing and evidence workflows | Reconcile with Kali companion and shared evidence model |

**Important:** Branch presence and commit history do not establish that a branch is merged, deployable, or current. Re-check branch heads and compare results immediately before every merge. No branch was merged or deleted as part of this register creation.

## 2. Feature ownership and verification matrix

Status meanings: **Implemented in branch** = code was located; **Partial / verify** = implementation exists but full product parity or end-to-end operation is not established; **Not verified** = requires direct test or further source review.

| Capability | Likely source | Current assessment | Required proof |
|---|---|---|---|
| Native HTTP/HTTPS proxy | Burp integration | Implemented in branch; maturity verification required | Live local browser-to-proxy-to-origin round trip; TLS trust and failure tests |
| Request interception | Burp integration | Implemented in branch | Pause, edit, forward, drop, timeout and concurrent-request tests |
| Response interception | Burp integration | Implemented in branch | Pause, edit, forward/drop; content-length, compression and streaming correctness |
| WebSocket text frames | Burp integration | Implemented in branch | Bidirectional frame pause/edit/forward/drop tests |
| WebSocket binary frames | Burp integration | Not verified / gap | Binary-safe editor and frame-integrity tests |
| Repeater | Burp integration | Implemented foundation | Repeat exact request, preserve headers/body, history, cancellation and response rendering |
| Burp Montoya connector | Burp integration | Implemented metadata/handoff paths | Compatibility test against supported Burp version; scope and auth tests |
| Intruder-style execution | Burp integration | Planner/parameter foundations only | Bounded execution engine, concurrency controls, rate limits, cancellation, results |
| Native crawler | Burp integration | Bounded crawler present | Authenticated session, robots/scope policy, redirect/DNS rebinding tests |
| Active web checks | Burp integration | Limited checks present | Per-check approval, safe target binding, reproducible findings and false-positive controls |
| Packet capture | Burp integration | Bounded tcpdump capture present | Real interface capture, permissions, PCAP integrity, quotas, retention and parser tests |
| Nmap scan jobs | Nmap milestone | Implementation present | Start/poll/cancel/recover lifecycle; target authorization and XML edge cases |
| Evidence and case exports | Forensics/Nmap/Burp | Several modules present | Cross-module schema consistency, hash verification, archive tamper tests |
| Disk imaging/recovery | Forensics | Implementation present | Read-only source guarantee, interrupted acquisition recovery, hashes and chain of custody |
| Kali command centre | Kali branch | Implementation present | Each of 12 options individually tested on supported OS/hardware |
| Remote device workflows | Kali branch | Partial / verify | Recipient-side consent, device identity, revocation, visible indicator and audit |
| Multimodal agent inputs | Agent branch | Implementation present | MIME sniffing, parser sandboxing, limits, prompt-injection and privacy tests |
| Model intelligence | Model branch | Implementation present | Provider failure/fallback, model capability checks, cost/time limits and deterministic evaluations |
| Multi-agent orchestration | Agent/model branches | Partial; current route selection includes keyword routing | Coordinator plan, specialist handoffs, tool authorization and evidence aggregation |

## 3. Confirmed code-level findings

### P0 — Authentication and trust boundaries

1. **Middleware fail-open when Supabase configuration is missing.** In `proxy.ts`, missing `NEXT_PUBLIC_SUPABASE_URL` or `NEXT_PUBLIC_SUPABASE_ANON_KEY` currently allows non-admin requests to continue. Protected pages and API routes must fail closed when auth configuration is absent.
2. **API-level authorization must not rely only on middleware.** Verify session and entitlement checks within sensitive route handlers and service functions. Test direct API calls with no session, expired session, inactive subscription and non-admin account.
3. **Local bridge pairing token permissions.** The bridge creates a restrictive token file, but the existing-token load path should reassert owner-only permissions and reject symlink/non-regular files. Add explicit rotation/revocation and tests.
4. **Bridge origin/auth boundaries.** Keep loopback binding, origin allow-list and constant-time token comparison. Validate every mutating endpoint independently; CORS is not authentication.
5. **SSRF and DNS rebinding.** For all URL-fetching/crawling/replay workflows, validate resolved addresses at connection time, reject prohibited address ranges, revalidate redirects and prevent DNS rebinding. Do not trust hostname validation alone.

### P1 — Reliability and evidence integrity

1. Consolidate duplicate CI jobs and make every relevant workflow run on pull requests as well as branch pushes.
2. Do not treat cancelled CI as green. Require a completed run for the exact head SHA before merge.
3. Standardize timeouts, bounded request bodies, response-size limits, cancellation and cleanup across companion modules.
4. Use a shared evidence envelope: case ID, artifact ID, source module, target/scope, operator/approval reference, timestamp, tool/version, raw evidence hash, parser version, observations, confidence, limitations and remediation.
5. Ensure report generation never upgrades an inference to a verified observation.
6. Add quotas and retention controls for PCAPs, disk images, recovered files, scan outputs and exported cases.
7. Make long-running operations resumable or safely cancellable; ensure locks are released and partial artifacts are clearly marked.

### P1 — Native web workbench parity

1. Complete HTTP/2 support and document protocol limitations.
2. Provide binary-safe request/response and WebSocket frame inspection/editing.
3. Finish Repeater with raw request fidelity, tabs, history, cancellation, response diff and export.
4. Build bounded Intruder-style execution with concurrency, delay, rate limits, cancellation and per-request scope checks.
5. Add authenticated crawling with explicitly configured session material and safe secret storage.
6. Add GraphQL/API workflow support and structured request collections.
7. Add vulnerability checks incrementally: each check must have an explicit scope, safe test profile, reproducible evidence, confidence, remediation and false-positive validation. Do not claim SQLi, SSRF or IDOR coverage until these workflows exist and pass tests.

### P1 — AI orchestration

1. Replace keyword-only specialist selection as the primary coordinator with a structured planner.
2. Separate planning from execution. A plan may propose tools, but only a policy gate can authorize execution.
3. Require each specialist to return typed evidence, source references, confidence, limitations and next-step proposals.
4. Prevent model output, retrieved pages, files and tool output from changing system policy or approval state.
5. Add evaluation fixtures for prompt injection, tool misuse, unsupported claims, hallucinated scans and cross-case data leakage.
6. Add provider timeouts, retries with budgets, fallback telemetry, token/cost limits and model capability validation.
7. Ensure the agent cannot claim a local tool ran unless a signed/validated companion result is supplied.

## 4. CI and release workflow target

### Required checks

- Web: lockfile-based install, lint, TypeScript, unit tests, production build.
- Python companion: full unit suite, type/static checks where configured, security-focused tests.
- Burp extension: Java/Gradle build, supported API compatibility checks, artifact integrity.
- OS/VM: shell syntax, build-definition tests, ISO build smoke test where runner capacity permits.
- Security: dependency audit, secret scanning, CodeQL or equivalent static analysis, and targeted SAST.
- Integration: API contract tests, browser-to-companion tests, auth/entitlement tests, end-to-end critical workflows.
- Release: exact-SHA green checks, signed/versioned artifacts, checksums, changelog and rollback instructions.

### Workflow hygiene

- Use one authoritative workflow for shared companion tests; avoid duplicate invocations across overlapping workflows.
- Use `npm ci` rather than `npm install` in CI where the committed lockfile is authoritative.
- Pin third-party GitHub Actions to reviewed immutable commit SHAs.
- Apply least-privilege workflow permissions.
- Use path filters carefully so changes to shared modules trigger all dependent checks.
- PR checks must run against the proposed merge result, not just an old branch snapshot.
- Cancel superseded runs for developer feedback, but require the final candidate run to complete successfully.

## 5. Integration order

Do not merge all feature branches at once. Use staged PRs with small, reviewable diffs:

1. **Foundation:** harden auth/bridge boundaries and establish shared contracts; preserve `main` behaviour.
2. **Evidence contract:** agree a versioned evidence schema and adapt Nmap, web testing and forensics producers/consumers.
3. **Native web stack:** integrate proxy/workbench, Repeater and Burp connector as separately reviewable slices.
4. **Nmap + Kali companion:** merge scan lifecycle and command-centre integrations without duplicating target/scope policy.
5. **Forensics:** merge acquisition/recovery and case export after chain-of-custody tests.
6. **Agent/model:** integrate multimodal inputs and model intelligence after tool registry, authorization and evidence contracts are stable.
7. **OS/VM and release:** verify packaging and installation against the integrated companion, not only feature-branch definitions.

For each PR: refresh base, inspect three-dot diff, check changed files and generated artifacts, run focused tests, run full required CI, manually verify critical workflows, then merge. Keep feature branches until their work is verified in the integration branch.

## 6. Definition of done

A capability is **Done** only when all applicable items are satisfied:

- [ ] Backend implementation exists and is reachable through a documented API.
- [ ] UI is connected to the real backend; no fake/simulated success state.
- [ ] Authentication, authorization, scope and consent controls are enforced server-side.
- [ ] Input, output, time, memory and concurrency are bounded.
- [ ] Unit and negative tests cover success, failure, timeout, cancellation and invalid scope.
- [ ] Integration test proves the real end-to-end workflow.
- [ ] Evidence is attributable, timestamped, integrity-checked and exportable where applicable.
- [ ] Logs avoid secrets and unnecessary sensitive content.
- [ ] Documentation describes limitations and supported environments.
- [ ] Required CI passes on the exact commit SHA.
- [ ] Deployment or packaged artifact is smoke-tested in its target environment.
- [ ] Rollback or recovery path is documented.

## 7. Immediate execution backlog

| ID | Priority | Task | Acceptance criteria |
|---|---|---|---|
| CL-INT-001 | P0 | Fix auth middleware fail-open | Protected paths return configuration error when Supabase config is absent; tests cover API and page paths |
| CL-INT-002 | P0 | Harden local bridge token loading | Existing token file type, symlink, owner and permissions validated; rotation tests pass |
| CL-INT-003 | P0 | Build shared branch/PR integration checklist | Every feature branch has current head SHA, base diff, owner, dependencies and required checks recorded |
| CL-INT-004 | P1 | Consolidate CI | One authoritative companion suite; PR triggers and path coverage validated |
| CL-INT-005 | P1 | Standardize evidence envelope | Nmap, web and forensics records validate against a versioned shared schema |
| CL-INT-006 | P1 | Verify native proxy end-to-end | HTTP, HTTPS, request/response pause, WebSocket and cancellation tests pass against local fixtures |
| CL-INT-007 | P1 | Harden URL-fetching workflows | Redirect, DNS rebinding, private IP, IPv6 and credential-leak tests pass |
| CL-INT-008 | P1 | Integrate Nmap lifecycle | Start/poll/cancel/recover and evidence export pass end-to-end |
| CL-INT-009 | P1 | Formalize agent tool policy | Planner cannot bypass authorization; tool results are provenance-bound |
| CL-INT-010 | P2 | Expand protocol parity | HTTP/2 and binary-safe workflows have explicit support and regression tests |
| CL-INT-011 | P2 | Add active testing engine | Controlled Intruder-style execution with rate limits, cancellation and per-request scope enforcement |
| CL-INT-012 | P2 | Complete forensics resilience | Interrupted imaging, hash verification, recovery manifests and case archive tamper tests pass |

## 8. Progress snapshot — 2026-11-18

| Backlog item | Status | Work |
|---|---|---|
| CL-INT-001 — Auth middleware fail-closed | **In review — PR #4** | Public-route policy isolated and tested; protected pages/APIs now return 503 when Supabase config is absent; admin routes remain concealed. GitHub Actions passed on the PR head and Vercel checks passed at the time checked. |
| CL-INT-002 — Local bridge token permissions | **In review — PR #5** | Token storage extracted; owner-only permissions, symlink rejection, malformed-token rejection and four regression tests added. GitHub CI was queued when last checked; not yet green. |
| CL-INT-003 — Branch/PR integration checklist | **Created — PR #3** | This register is the initial checklist and branch ownership record. |
| CL-INT-004 onward | **Not started** | Continue in dependency order; re-check exact branch heads and PR checks before implementation. |

PR links:
- [PR #3 — Integration and gap register](https://github.com/abelmiracle377-stack/cyberlab-ai/pull/3)
- [PR #4 — Fail-closed authentication middleware](https://github.com/abelmiracle377-stack/cyberlab-ai/pull/4)
- [PR #5 — Secure bridge pairing token storage](https://github.com/abelmiracle377-stack/cyberlab-ai/pull/5)

## 9. Audit caveats and next review requirements

- Branches are moving targets. Re-fetch all branch heads and compare against the current integration base before taking action.
- Historical commit counts include shared ancestry and must not be summed as unique commits.
- A branch's latest successful CI run does not prove its current head is green unless the check run's SHA matches that exact head.
- A Vercel status failure must be investigated from deployment logs; do not infer the root cause from a status badge.
- This register does not authorize merging, deleting branches, changing production configuration, running active scans, or accessing user devices.
- Keep this file updated in every integration PR when a task's status, implementation owner, test evidence or known limitation changes.

## 10. Source locations reviewed

- `proxy.ts`
- `app/api/agent/route.ts`
- `lib/agent-orchestrator.ts`
- `kali-companion/bridge.py`
- `kali-companion/network_capture.py`
- `kali-companion/tests/test_network_capture.py`
- `kali-companion/burp_connector.py`
- `.github/workflows/ci.yml`
- `.github/workflows/burp-integration.yml`
- `.github/workflows/agent-inputs-ci.yml`
- `docs/ADDITIVE_FEATURE_PARITY_ROADMAP.md`
- `docs/NATIVE_WEB_WORKBENCH.md` on the Burp feature branch

---

**Operating principle:** CyberLab AI should be treated as one integrated security workstation with a single authorization model, shared evidence model, coordinated specialist agents and reproducible tool execution—not a collection of loosely connected feature branches.
