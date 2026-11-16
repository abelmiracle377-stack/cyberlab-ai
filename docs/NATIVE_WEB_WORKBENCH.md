# CyberLab Native Web Workbench

The local companion exposes a native HTTP request workbench at `POST /web/request` and process-memory history at `GET /web/history`. It does not require Burp Suite or another proxy.

## Phase 1 capabilities

- HTTP/1.1 request composition for GET, HEAD, OPTIONS, POST, PUT, PATCH and DELETE.
- Bounded headers and UTF-8 request body (16 KB maximum).
- Exact hostname confirmation, written-authorisation reference and explicit send approval.
- A separate confirmation for methods that can change server state.
- DNS resolution is pinned to the selected address for the connection. Public mode rejects non-global addresses and mixed public/private DNS results. Local-lab mode accepts loopback only.
- TLS certificate verification remains enabled.
- Redirects are not followed automatically.
- Response bodies are capped at 256 KB.
- Last 25 request/response records remain in companion process memory only; they are not written to disk or sent to an AI provider automatically.

## Endpoints

- `POST /web/request`: authenticated request execution.
- `GET /web/history?limit=20`: authenticated in-memory history.

The bridge remains bound to loopback and requires the existing pairing token and an allowed browser origin.

## Deliberate limitations

This is a request workbench, not yet a full interception proxy, crawler, active vulnerability scanner, Intruder-equivalent fuzzer, WebSocket inspector or automated assessment engine. HTTPS CONNECT interception, a local CA, HTTP/2 and WebSocket support are not implemented in this phase. Test with an intentionally vulnerable local lab first.
