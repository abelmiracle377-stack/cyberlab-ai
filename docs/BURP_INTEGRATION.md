# CyberLab AI — Burp Suite Integration

## Deployment boundary

Burp Suite runs as a desktop application on the paired Kali workstation. CyberLab's web dashboard talks to the existing loopback-only Kali companion; it does not host Burp in the browser and does not install or modify the CyberLab VM OS.

## Current implementation status

The first integration slice provides:

- Burp executable detection through the existing tool inventory.
- A read-only health probe for Burp's desktop REST API.
- Loopback-only API URL validation.
- API-key loading from a local file or process environment.
- Paired Kali bridge endpoints: `GET /burp/status`, `GET /burp/proxy/history`, and `GET /burp/site-map`.
- Explicit states for missing configuration, unreachable service, authentication failure, invalid configuration and successful connection.
- No Burp API key or extension token is returned in responses or logs.
- A first-party Montoya extension exposes `GET http://127.0.0.1:8766/v1/health` and `GET http://127.0.0.1:8766/v1/proxy/history?limit=50` and `GET http://127.0.0.1:8766/v1/site-map?limit=50` and `GET http://127.0.0.1:8766/v1/issues?limit=50`, authenticated by a local random bearer token.
- Proxy history and site-map exports are metadata-only, in-scope-only and capped at 100 items each. The `/burp-suite` dashboard page displays these results.
- Read-only retrieval of existing site-map audit issue names, severity, confidence and base URL, limited to issues with at least one associated in-scope request.
- A separately confirmed Repeater handoff can place one in-scope captured request into Burp Repeater. Burp does not send it; the analyst must review it and manually click Send.

The Montoya extension now exposes bounded, read-only metadata from Burp Proxy HTTP history. It exports only requests that Burp itself marks in scope, and redacts common credential-like query parameters. It does not export raw request/response headers or bodies. The following capabilities are **not implemented yet**: in-dashboard request/response editing, automated Repeater replay, Intruder task execution, active scanning, crawl tasks, issue mutation, full issue-detail export or automated remediation.

## Kali-side setup

1. Install and launch Burp Suite on the paired Kali workstation.
2. In Burp, open **Settings → Suite → REST API settings**.
3. Enable the REST API service and bind it to `127.0.0.1` only. Do not bind it to all interfaces.
4. Create a dedicated API key for CyberLab. Keep API-key authentication enabled.
5. Store the key in `~/.config/cyberlab/burp-api-key` and restrict the file to its owner:

   ```bash
   mkdir -p ~/.config/cyberlab
   chmod 700 ~/.config/cyberlab
   umask 077
   read -rsp "Burp API key: " BURP_KEY; echo
   printf '%s' "$BURP_KEY" > ~/.config/cyberlab/burp-api-key
   unset BURP_KEY
   chmod 600 ~/.config/cyberlab/burp-api-key
   ```

6. If Burp uses a non-default loopback port, set `CYBERLAB_BURP_API_URL` for the Kali companion process, for example `http://127.0.0.1:1337`.
7. Build `burp-extension` from the repository root with JDK 21 and Gradle (`gradle -p burp-extension clean jar`). Load `burp-extension/build/libs/cyberlab-burp-connector-0.1.0.jar` in Burp under **Extensions → Installed → Add**. The passing GitHub Actions workflow also publishes this JAR as the `cyberlab-burp-extension` artifact for 14 days.
8. The extension binds only to `127.0.0.1:8766` and creates `~/.config/cyberlab/burp-extension-token` with owner-only permissions. Do not share this token.
9. Restart the Kali companion and request `GET /burp/status`, `GET /burp/proxy/history?limit=50`, and `GET /burp/issues?limit=50` through the paired bridge.

The API key is never sent to the hosted AI model. Do not paste it into chat, dashboard prompts, source control, or issue reports.

## Status semantics

- `connected`: the configured local REST API endpoint returned a successful response. This does not prove that a scan or any other Burp capability is available.
- `not_configured`: no API key is available to the companion.
- `unavailable`: the local REST API could not be reached.
- `authentication_failed`: Burp rejected the API key.
- `api_error`: Burp responded with a non-success status other than an authentication failure.
- `invalid_configuration`: the URL, key or other local configuration failed validation.

Burp edition is reported as `unknown` until it can be verified. Scanner capability is reported as `not_implemented`; Burp Professional's scanner must not be inferred from a successful health check.

## Security requirements for subsequent phases

- Keep Burp REST API bound to loopback and keep API-key authentication enabled.
- Do not expose Burp's REST API directly to the internet or the hosted dashboard.
- Keep the Burp API key in local owner-only storage; never return it through bridge responses.
- Preserve the companion's pairing token, origin allowlist, request-size limits and audit trail.
- Require an explicit engagement reference, exact target confirmation and in-scope validation before active requests.
- Treat proxy history, cookies, authorization headers, request bodies and scanner findings as sensitive evidence; redact secrets before model analysis.
- Never run active scans or Intruder jobs merely because the AI mentions them. Repeater handoff requires a separate user confirmation and only places an in-scope captured request in the Repeater tab; it does not send the request. Any replay is manually initiated by the analyst inside Burp.
- Do not add unrestricted shell execution to the Burp connector.
- Keep the Montoya connector bound to loopback, require bearer authentication, stop its server on extension unload, and never return out-of-scope proxy entries.

## Next implementation phases

1. Add a first-party CyberLab Montoya extension with authenticated loopback endpoints. Do not depend on an unauthenticated third-party REST extension.
2. Add pagination and stronger query filtering for proxy-history and site-map retrieval; bounded read-only metadata and existing audit-issue retrieval are now implemented.
3. Add a provenance-preserving evidence sync for selected Burp issues into CyberLab cases, with analyst review before any report is finalized.
4. Add Intruder task preparation with strict request-count and rate ceilings; require approval before sending.
5. Add Professional-edition scanner detection, crawl/audit task creation and task/result polling, with an explicit edition gate.
6. Link verified requests, responses and findings to CyberLab cases, evidence provenance and reports.
7. Add integration tests against a disposable local test application and a test Burp project; verify existing companion endpoints remain unchanged.
