# CyberLab AI — Burp Suite Integration

## Architecture

Burp Suite runs as a desktop application on the paired Kali workstation. CyberLab's web dashboard talks only to the authenticated local Kali companion. Neither Burp's REST API nor the Montoya extension listener is exposed to the internet.

CyberLab checks two separate local services:

- **Burp REST API** — GET /burp/status checks the configured API key against the loopback REST API endpoint (default http://127.0.0.1:1337). This proves only that the REST API answered; it does not identify the Burp edition or prove that Scanner/Intruder is licensed.
- **CyberLab Montoya extension** — GET /burp/extension/status checks the local extension health endpoint at http://127.0.0.1:8766/v1/health using the extension's owner-only bearer token. This is the health check for the CyberLab integration features.

The dashboard displays these checks independently so a working REST API cannot be mistaken for a loaded CyberLab extension, or vice versa.

## Current implemented capabilities

The first-party Montoya extension provides authenticated, loopback-only endpoints:

- GET /v1/health — authenticated extension health and capability declaration.
- GET /v1/proxy/history?limit=50 — bounded, in-scope proxy-history metadata.
- GET /v1/site-map?limit=50 — bounded, in-scope site-map metadata.
- GET /v1/issues?limit=50 — existing in-scope issue name, severity, confidence and base URL.
- POST /v1/repeater/from-history?id=<id>&confirm=true — place one captured in-scope request in Repeater; it is not sent.
- POST /v1/send-request?id=<id>&confirm=true — replay one captured in-scope request through Burp and return status/MIME/length metadata only.
- POST /v1/intruder/from-history?id=<id>&confirm=true&authorizationReference=<ref> — place one approved in-scope request in the native Intruder tab; does not start an attack.
- POST /v1/scanner/crawl?url=<url>&confirm=true&authorizationReference=<ref> — start a real Burp Professional crawl-only task for an existing in-scope URL.
- POST /v1/scanner/audit?url=<url>&confirm=true&authorizationReference=<ref> — start a real Burp Professional active-audit task for an existing in-scope URL.
- GET /v1/scanner/tasks — report current-session task IDs and bounded progress counters.
- POST /v1/scanner/cancel?id=<task-id>&confirm=true — request deletion/cancellation of a tracked task.

The paired companion exposes corresponding authenticated routes:

- GET /burp/status
- GET /burp/extension/status
- GET /burp/proxy/history
- GET /burp/site-map
- GET /burp/issues
- POST /burp/repeater/from-history
- POST /burp/send-request
- POST /burp/intruder/from-history
- POST /burp/scanner/crawl
- POST /burp/scanner/audit
- GET /burp/scanner/tasks
- POST /burp/scanner/cancel

The dashboard refresh checks both health endpoints and retrieves the three metadata feeds. Repeater handoff and replay each have a separate explicit confirmation. Replay re-sends live traffic; the extension rechecks Burp's in-scope flag before acting. The dashboard receives response metadata only, not request or response bodies.

Proxy history and site-map exports are in-scope-only, bounded to 100 entries at the connector, and redact common credential-like query parameters. The extension does not export raw request/response headers or bodies.

## Current active capabilities

The first-party Montoya extension and paired companion now provide:

- Intruder handoff: an explicitly approved, in-scope proxy-history request is placed in the native Intruder tab. The analyst configures payload positions, payload sources and attack settings, then starts the attack in Burp. Montoya exposes the handoff but not a complete programmatic Intruder attack-start API; CyberLab does not claim to execute the Intruder attack itself.
- Professional crawl-only: a confirmed URL already included in Burp Suite scope is passed to Burp Scanner's real crawl task.
- Professional active audit: a confirmed in-scope URL is passed to Burp Scanner's real active-audit task using Burp's built-in legacy active-audit checks.
- Scanner task status: current-session task IDs, request counts, error counts and audit issue counts can be polled from CyberLab.
- Scanner task cancellation: the operator can request task deletion/cancellation through the extension.

Every Intruder handoff, crawl and active audit requires explicit confirmation and an authorisation/lab reference. The extension rechecks Burp's existing Suite scope and never adds a target to scope automatically. Scanner features require a compatible Burp Professional licence; Community edition does not gain Scanner by loading the extension. Task tracking is held in extension memory and resets when the extension unloads or Burp restarts.

## Still native to Burp desktop

These features are not reproduced as complete CyberLab interfaces:

- Intruder payload-position editing, payload set management, attack-type configuration, live attack execution and full result-table analysis. The request handoff opens the real Intruder tool; the analyst configures and launches the attack in Burp.
- Full request/response editor, complete Repeater editing and history, Sequencer, Decoder, Comparer, Burp browser and extension manager.
- Advanced custom scan configurations, authenticated crawl/login sequence configuration and complete scan result detail/report workflows.
- Full raw issue evidence export, issue mutation and automated remediation.

The CyberLab workspace is an integration surface over the Burp desktop engine, not a replacement for every native Burp UI capability.

## Kali-side setup

1. Install and launch Burp Suite on the paired Kali workstation.
2. In Burp, open **Settings → Suite → REST API settings**.
3. Enable the REST API service and bind it to 127.0.0.1 only. Do not bind it to all interfaces.
4. Create a dedicated API key for CyberLab. Keep API-key authentication enabled.
5. Store the key in ~/.config/cyberlab/burp-api-key and restrict the file to its owner:

   bash
   mkdir -p ~/.config/cyberlab
   chmod 700 ~/.config/cyberlab
   umask 077
   read -rsp "Burp API key: " BURP_KEY; echo
   printf '%s' "$BURP_KEY" > ~/.config/cyberlab/burp-api-key
   unset BURP_KEY
   chmod 600 ~/.config/cyberlab/burp-api-key

6. If Burp uses a non-default loopback port, set CYBERLAB_BURP_API_URL for the Kali companion process.
7. Build the extension from the repository root with JDK 21 and Gradle: gradle -p burp-extension clean jar.
8. Load burp-extension/build/libs/cyberlab-burp-connector-0.1.0.jar in Burp under **Extensions → Installed → Add**.
9. The extension binds only to 127.0.0.1:8766 and creates ~/.config/cyberlab/burp-extension-token with owner-only permissions. Do not share this token.
10. Restart the Kali companion, pair it with CyberLab, open **Burp Suite workspace**, and select **Refresh Burp data**.

The API key and extension token stay on the paired workstation. Never paste either secret into chat, dashboard prompts, source control or issue reports.

## Status semantics

Burp REST API states:

- connected: the configured local REST API endpoint returned a successful response.
- not_configured: no API key is available to the companion.
- unavailable: the local REST API could not be reached.
- authentication_failed: Burp rejected the API key.
- api_error / invalid_configuration: the service responded with an error or local configuration failed validation.

Montoya extension states:

- connected: the authenticated local extension health endpoint returned the expected Montoya connector identity.
- not_configured: the local extension token file is absent.
- unavailable: the extension health listener could not be reached.
- authentication_failed: the extension rejected the bearer token.
- invalid_response / invalid_configuration: the health payload or local token failed validation.

## Security requirements

- Keep both listeners bound to loopback; never expose them directly to the internet.
- Keep the Burp API key and extension token in owner-only local files.
- Preserve the companion pairing token and origin allowlist.
- Recheck Burp's in-scope status for every request action.
- Require explicit confirmation for Repeater handoff and every live replay.
- Treat proxy history, cookies, authorization headers, request bodies and scanner findings as sensitive evidence. Redact secrets before model analysis.
- Never run active scans or Intruder jobs merely because the AI mentions them.
- Do not add unrestricted shell execution to the Burp connector.

## Next implementation phases

1. Add richer task lifecycle/status reporting when the Montoya API exposes reliable completion semantics across supported Burp versions.
2. Add request/response evidence capture with aggressive redaction and provenance-preserving case linkage.
3. Add configurable scan profiles and authenticated scan setup only after the edition/configuration APIs are verified and exposed with per-target approval.
4. Add integration tests against a disposable local test application and a licensed test Burp Professional project before expanding active execution.
