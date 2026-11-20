# CyberLab AI repository and deployment audit

Audit date: 2026-11-18
Repository: `abelmiracle377-stack/cyberlab-ai`
Current production project: `cyberlab-ai` on Vercel
Current production source: `feat/crypto-wallet-recovery-lab` at `4622ec6954445713a3e5b3cfd4a1c2669e3d4f4a`
Production deployment: `dpl_AaGTizqbTAQhUL9WqiWqcAecLvmK` (READY; alias `cyberlab-ai.vercel.app`)

## Executive result

The current production deployment is the wallet/Solidity feature branch, not a unified release of all repository work. It includes the existing mainline application and the Solidity Lab plus local wallet-backup triage. The production deployment built successfully and is READY, but runtime logs show the admin-auth API failing because Supabase is not configured. Vercel environment metadata also showed an empty `OPENROUTER_API_KEY`. Do not describe authenticated/database-backed or hosted-model flows as operational until those values are configured and verified.

The repository has 13 feature and maintenance branches plus the new integration branch. Several independent feature branches have READY Vercel preview deployments, but a preview deployment is not production. The branches have diverged substantially. A blind merge or production deployment from one feature branch would replace or omit work from the currently deployed branch.

The integration branch now contains the wallet/Solidity release plus additive imports from the native Burp/web workstream, local forensics/OS definitions, camera intelligence, the optional VPS gateway, Nmap evidence parity, bounded agent file attachments/audio transcription, fail-closed authentication and secure local pairing-token storage. Shared files were reconciled selectively rather than overwritten wholesale. The latest integration preview is building; the full companion, Kali gateway and web CI suites are still running. This integration branch has not been promoted to production.

## Branch inventory and deployment disposition

| Branch | Workstream / status | Production disposition |
|---|---|---|
| `main` | Mainline CyberLab dashboard, security modules and ongoing fixes. The current main head is behind the wallet release branch. | Not the current production source. Its latest observed Vercel check failed with a build-rate-limit status. |
| `feat/model-intelligence-workspace` | Earlier model/agent workspace base. | Ancestor work carried into the wallet/Solidity production branch. |
| `feat/crypto-wallet-recovery-lab` | Solidity Lab, registries, agent orchestration updates, wallet backup triage and migrations. | Current production source; Vercel READY. |
| `feature/cyberlab-burp-integration` | Native loopback HTTP/HTTPS interception, manual request/response decisions, WebSocket inspection, native web testing/scanning, crawler, network capture, forensics and companion modules. | Source modules and UI routes imported into the integration branch; not yet production. |
| `fix/native-web-scope-and-ssrf-tests` | Exact-origin approval and SSRF/DNS-rebinding regression coverage on the Burp workstream. | Updated web-testing source and tests imported into integration; not yet production. |
| `feature/additive-forensics-recovery` | Local file/image recovery, evidence/case management, read-only disk inventory, guarded imaging and image-analysis workflows; includes OS/VM build definitions. | Forensics UI, companion modules and OS/VM build definitions imported into integration; physical-disk workflows still require the paired local Linux/Kali companion. |
| `feature/kali-command-centre` | Local Kali command centre, camera intelligence and a separate consent-based VPS gateway. | Camera modules and CLI entry points plus VPS gateway source imported into integration. PR #1 remains mergeability-blocked. The VPS gateway is a separately installed service and has not been installed or deployed. |
| `feature/agent-multimodal-inputs` | Multimodal agent input work. | Bounded image/PDF/text attachment support and audio transcription UI/API imported into integration. Provider credentials are still required; not production. |
| `milestone/nmap-evidence-parity` | Nmap evidence/report parity updates across the network-analysis UI and companion. | Parser, report UI, bridge evidence fields and parity tests imported into integration; not production. |
| `fix/auth-middleware-fail-closed` | Fail-closed authentication behaviour and tests for missing Supabase configuration. | Middleware and regression tests integrated into the integration branch; PR #4 remains open/draft. |
| `fix/bridge-token-permissions` | Local companion pairing-token file/permission hardening. | Secure token persistence module, tests and bridge integration applied to the integration branch; PR #5 remains open/draft. |
| `docs/integration-gap-register` | Repository integration and security-gap register. | Documentation PR #3 open/draft; no functional deployment effect. |
| `integration/cyberlab-unified-workstation` | Unified release candidate based on the current production source. | Contains the wallet/Solidity base, native web/forensics modules, bridge route reconciliation, camera and VPS source, Nmap evidence parity, multimodal inputs, auth/bridge hardening and expanded CI triggers. Preview/CI validation is in progress; not production. |

## Pull request inventory

| PR | Head branch | Base | GitHub state | Vercel head check |
|---|---|---|---|---|
| #1 Kali command centre | `feature/kali-command-centre` | `main` | Open, not merged, mergeable=false | Success |
| #2 Forensics recovery | `feature/additive-forensics-recovery` | `main` | Open, draft, mergeable=true | Success |
| #3 Integration gap register | `docs/integration-gap-register` | `main` | Open, draft, mergeable=true | Success |
| #4 Auth fail-closed | `fix/auth-middleware-fail-closed` | `main` | Open, draft, mergeable=true | Success |
| #5 Bridge token permissions | `fix/bridge-token-permissions` | `main` | Open, draft, mergeable=true | Success |
| #6 Native web SSRF/origin scope | `fix/native-web-scope-and-ssrf-tests` | `feature/cyberlab-burp-integration` | Open, draft, mergeable=true | Success |
| #7 Solidity and wallet triage | `feat/crypto-wallet-recovery-lab` | `main` | Open, draft, mergeable=true | Success |

The reported checks above are Vercel deployment checks; they are not proof that the full GitHub Actions/unit-test suite passed. PR #1 has an explicit mergeability conflict/blocker. PR #7 remains open/draft even though its branch is deployed to production directly.

## Branch divergence

The deployed wallet branch is 136 commits ahead of `main` and has no commits behind it. The Burp branch and the wallet branch are heavily divergent: comparing wallet as base with Burp as head reports 730 commits unique to the Burp branch and 136 commits unique to the wallet branch. The additive forensics, multimodal, Kali command-centre, Nmap and security-fix branches also contain work not present in the wallet release. The integration branch was created from the wallet branch and now contains additive feature imports and reconciled shared-file changes. It remains separate from production pending validation.

This divergence is why merging an entire feature branch or deploying its preview SHA directly to production is unsafe: doing so could drop the wallet/Solidity release or overwrite shared agent, navigation, API, CSS, bridge and CI files.

## Verified production deployment

- Vercel deployment state: READY.
- Production alias: `cyberlab-ai.vercel.app`.
- Git source: `feat/crypto-wallet-recovery-lab` at `4622ec6954445713a3e5b3cfd4a1c2669e3d4f4a`.
- Build logs showed successful dependency installation, Next.js production compilation, TypeScript checks and 59/59 static pages.
- Solidity and wallet-recovery routes were included in that build.
- Runtime log inspection found `GET /api/admin/auth` failing with `Supabase is not configured.`
- Environment-variable metadata showed only `OPENROUTER_API_KEY`, with an empty value. No Supabase project URL, anon key or service-role key was configured.
- Required setup before claiming full production readiness: configure `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY` and a valid `OPENROUTER_API_KEY` directly in Vercel; apply the two wallet-branch migrations in order:
  1. `supabase/migrations/202611140001_ai_usage_gateway.sql`
  2. `supabase/migrations/202611140002_expand_ai_usage_reservations.sql`
  3. `supabase/migrations/202611150001_admin_ai_learning_control.sql`
- No database migration has been applied by this audit. The additional admin AI-learning migration is now present on the integration branch but also requires explicit application after the two wallet migrations.

## Integration priorities

1. Keep the wallet/Solidity production release intact as the integration base.
2. Integrate and review the auth fail-closed policy before enabling protected production workflows.
3. Integrate bridge-token permission hardening without losing the wallet branch's bridge changes.
4. Port the native Burp companion modules and their dependency graph, including the exact-origin/SSRF fix and the WebSocket partial-frame timeout fix, then run all companion tests.
5. Port forensics recovery and OS/VM build definitions, reconciling shared `bridge.py`, `cyberlab.py`, tool registry, navigation, CSS and CI changes.
6. Nmap evidence parity and bounded multimodal file/audio input are now integrated; verify their end-to-end flows and provider behaviour.
7. Camera intelligence is available as an explicitly authorised local companion CLI feature. The VPS gateway source is present but must remain opt-in and requires a separately provisioned VPS, owner token, TLS and reviewed device permissions before installation.
8. Resolve PR #1's mergeability issue and review the separate VPS gateway deployment/consent/security model.
9. Finish the combined GitHub Actions suites and full Vercel preview build from the integration branch. Deploy to production only after checks pass and database/provider configuration is complete.

## Scope and limitations

This is a source-control, integration and deployment metadata audit. It does not claim every feature has been manually exercised end-to-end. READY Vercel previews prove a build/deployment completed, not that local hardware, external providers, Supabase, credentials, OS imaging, live packet capture, or remote gateway infrastructure are configured. No wallet secrets, production credentials, physical disks or external targets were accessed.
