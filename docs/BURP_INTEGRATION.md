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

The paired companion exposes corresponding authenticated routes:

- GET /burp/status
- GET /burp/extension/status
- GET /burp/proxy/history
- GET /burp/site-map
- GET /burp/issues
- POST /burp/repeater/from-history
- POST /burp/send-request

The dashboard refresh checks both health endpoints and retrieves the three metadata feeds. Repeater handoff and replay each have a separate explicit confirmation. Replay re-sends live traffic; the extension rechecks Burp's in-scope flag before acting. The dashboard receives response metadata only, not request or response bodies.

Proxy history and site-map exports are in-scope-only, bounded to 100 entries at the connector, and redact common credential-like query parameters. The extension does not export raw request/response headers or bodies.

## Not yet integrated into CyberLab

These are native Burp features, not current CyberLab workspace capabilities:

- Intruder attack configuration and execution.
- Burp Scanner active scan creation, scan control and result polling.
- Burp crawling orchestration.
- Full request/response editing inside CyberLab.
- Full raw issue evidence export, issue mutation and automated remediation.
- Recreating Burp's Sequencer, Decoder, Comparer, browser or extension-manager interfaces.

Use the Burp desktop application for those functions. Availability depends on the installed Burp edition; a successful REST API check does not establish that a Professional-only feature is available. The CyberLab workspace is an integration surface, not a replacement for the Burp desktop application.

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

1. Add edition-aware Intruder task preparation with strict request-count and rate ceilings, followed by a separately approved execution path.
2. Add Burp Professional scanner/crawl task creation and result polling, gated by verified edition and exact in-scope targets.
3. Add reviewed request/response evidence capture with redaction and provenance-preserving case linkage.
4. Add integration tests against a disposable local test application and a test Burp project before enabling additional active workflows.
