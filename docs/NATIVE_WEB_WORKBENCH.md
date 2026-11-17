# CyberLab Native Web Workbench

CyberLab's web assessment direction is native-first. Burp Suite is not a required dependency or execution backend. The optional Burp metadata connector remains a separate interoperability feature and is not used by the native workbench.

## Native HTTP request workbench

The local Kali companion provides a scope-bound HTTP request sender and short-lived in-memory request history. Requests require:
- An exact target hostname confirmation.
- Written-authorisation confirmation and an engagement reference.
- A separate send approval.
- DNS resolution checks and pinned IP connection.
- Bounded request and response sizes and timeouts.
- No automatic redirect following.
- A separate confirmation for state-changing HTTP methods.

## Native request repeater foundation

The native HTTP workbench can load an in-memory request-history item back into the editor for an explicitly approved replay. History retains safe request metadata only: sensitive request and response headers are redacted, response bodies are omitted, and URL query strings are omitted to avoid retaining credentials or tokens embedded in parameters. Request-body contents are not retained either. If the original request had a body or query string, the UI tells the operator to re-enter it. The live response remains visible in the current workbench session, but is not kept in history. Loading a history item never sends it automatically; scope and send approval are required again.

## Native request repeater (first implementation)

The `/web-repeater` workbench provides up to five browser-session request tabs. Operators can create or duplicate a tab, edit the URL, method, headers and UTF-8 body, and explicitly send each request through the same native `POST /web/request` engine. Each send repeats the hostname confirmation, written-authorisation reference and state-changing-method approval checks. The repeater does not automatically replay requests, follow redirects or bypass the companion's DNS pinning, address policy, timeouts or request/response size limits.

Responses are retained only in the active browser session and can be compared by status, response headers and body text. The companion's own request history remains metadata-only; response bodies are not persisted there. This first implementation supports ordinary text requests and responses, not raw binary editing, response editing, HTTP/2, WebSockets or automated parameter mutation/fuzzing.

## Native bounded crawler and baseline audit

The companion's `POST /web/crawl` endpoint runs `kali-companion/web_crawler.py`. It:
- Requires the exact scheme, hostname and port to be retyped, written authorisation, an engagement reference and explicit run approval.
- Uses the native CyberLab HTTP sender; it does not invoke Burp Suite or another proxy.
- Sends GET requests only, with a configurable delay and hard limits of 20 pages, depth 2 and 45 seconds.
- Revalidates the target address policy for every page.
- Follows same-origin links only; out-of-origin links are counted and blocked.
- Does not follow redirects, submit forms, inject payloads or attempt exploitation.
- Inventories forms without submitting them.
- Records status, content type, response size and a SHA-256 digest of the response body.
- Reviews baseline security headers and cookie attributes.

The baseline findings are indicators, not proof of exploitability. A missing header is not automatically a vulnerability in every deployment.

## Native safe active checks

The companion's `POST /web/active-scan` endpoint runs `kali-companion/web_active_scan.py`. It is a deliberately limited active-check layer:
- Requires written authorisation, exact scheme/host/port confirmation, an engagement reference and a separate active-run approval.
- Accepts up to 10 same-origin URLs and sends no more than 10 requests per run, with a delay and a 30-second runtime limit.
- Sends only OPTIONS CORS preflight requests and GET query-parameter reflection probes.
- Uses a reserved `.invalid` Origin value for CORS testing; it does not contact that domain.
- Skips query parameter names that look sensitive (token, key, auth, password, secret, session, code, signature, JWT, CSRF or nonce).
- Counts failed request attempts against the request budget.
- Does not submit forms, send state-changing methods, follow redirects, execute script or inject exploit payloads.
- Records response digests and reports only potential indicators for manual verification.

These checks are not a full vulnerability scanner. Reflection does not prove XSS, and permissive CORS headers do not by themselves prove sensitive data exposure.

## Agent Console handoff

The Agent Console recognises explicit web assessment requests that include an HTTP(S) URL and opens a local approval panel. After the operator confirms the exact origin, written-authorisation reference and crawl approval, the browser calls the paired loopback companion directly. The operator can separately approve the limited active checks. Returned crawl and scanner evidence is then submitted to the selected AI model for interpretation. The server-side model does not receive the bridge token and cannot silently initiate local requests. This is a user-approved workflow handoff, not yet autonomous specialist-agent execution or full finding verification.

## Native HTTP/HTTPS interception proxy (first implementation)

The paired local bridge exposes proxy controls through `/proxy/status`, `/proxy/start`, `/proxy/stop` and `/proxy/history`. The workbench provides the explicit scope and start/stop controls. The proxy:
- Binds only to `127.0.0.1`; it is not an open network proxy.
- Requires an exact origin to be retyped, written-authorisation confirmation, an engagement reference and a separate start approval. POST, PUT, PATCH and DELETE are blocked unless the operator separately approves forwarding state-changing methods.
- Optional manual interception pauses each request in a bounded in-memory queue (20 requests maximum). The operator can forward unchanged, edit the method/path/headers/UTF-8 body and forward the edited request, or drop it. Edited paths remain origin-form and cannot change the approved host, scheme or port; Host, Content-Length and hop-by-hop headers are managed by CyberLab. State-changing methods remain blocked unless separately approved at proxy start. Sensitive header values are redacted in the editor; leaving the [REDACTED] marker unchanged preserves the original value. Binary request bodies cannot be edited in the text editor. Pending request contents are held in companion memory only and are removed after a decision, timeout or proxy stop. Undecided requests are dropped after 120 seconds.
- Optional manual response interception is separately approved at proxy start. Each origin response pauses before it reaches the browser in a second bounded in-memory queue (20 responses maximum). The operator can inspect the status, reason, redacted headers and up to 16 KB of a UTF-8 text-like response body, then forward or drop it. Binary or non-UTF-8 bodies are not previewed. The full response remains only in the paused handler's memory; preview data is removed from the queue after a decision, timeout or proxy stop. Undecided responses are dropped after 120 seconds. The operator may also edit the status code, reason phrase, response headers and eligible UTF-8 text body before forwarding. Content-Length and hop-by-hop headers remain managed by CyberLab; redacted unchanged sensitive header values preserve their originals. Binary, non-UTF-8 or larger-than-16-KB bodies cannot be edited. When a body is edited, stale content encodings and validators are removed; bodyless status codes are relayed without a body.
- Enforces that exact scheme/host/port for every request and blocks other hosts, including cross-origin redirects when the browser follows them.
- Supports HTTP/1.1 absolute-form HTTP requests and HTTPS CONNECT with TLS termination using a CyberLab-issued exact-host certificate.
- Validates the upstream HTTPS certificate using the operating system's normal trust roots and pins the resolved address for each upstream connection.
- Forwards request and response bodies but never retains body contents in proxy history. History redacts credentials, cookies, token-like headers, redirect locations and URL query strings. The workbench provides searchable session history with method/status filters and a detail view for redacted request/response headers, body lengths and timing. A selected entry can be loaded into the native Repeater as an unsent draft; query strings, bodies and redacted credentials are deliberately not restored, and the Repeater still requires fresh authorisation and explicit send approval.
- Uses bounded header sizes, request bodies (64 KB), response bodies (2 MB) and network timeouts; oversized responses are rejected rather than partially relayed.
- Requires a local CA created by explicit approval. The operator must manually install the public CA certificate in a dedicated test browser profile; CyberLab never changes system/browser trust stores or exports the private key.

This is an initial HTTP/1.1 proxy, not full Burp parity. It supports up to 50 sequential HTTP/1.1 requests on one client connection, including ordered processing of pipelined requests; each request is independently checked against the exact approved origin and Host header. HTTP/1.0 keep-alive is supported only when explicitly requested. The proxy closes the client connection after the request limit or on protocol errors. It does not support HTTP/2, client certificates, or multi-origin scope profiles. Chunked HTTP/1.1 request bodies are decoded within a strict size limit; chunked upstream responses are decoded and reframed with a Content-Length after bounded buffering. RFC 6455 WebSocket version 13 upgrades are validated and tunnelled bidirectionally. A bounded frame observer records direction, FIN flag, opcode, mask flag, payload length and message-fragment relationships; it never stores or exposes payload bytes. An optional WebSocket frame interception mode is now connected to the live relay and workbench. It must be separately enabled and approved when starting the proxy, and cannot be combined with HTTP request/response pause modes. Each complete frame is decoded and paused in a bounded 20-item queue for up to 30 seconds. Complete UTF-8 text messages up to 64 KB can be edited, including messages split across up to 128 WebSocket frames. Incomplete fragmented messages are discarded and the tunnel is closed if assembly exceeds 15 seconds. CyberLab reassembles fragmented messages before presenting them; edited messages are rebuilt as a single valid text frame. Binary messages cannot be edited. Control frames are forwarded promptly while a fragmented message is being assembled so ping/pong traffic is not held for operator review. Client frames are remasked when rebuilt. A timeout closes the WebSocket tunnel rather than silently forwarding undecided data. Frames larger than 64 KB close the tunnel while this mode is enabled. Dropping a continuation, non-final or close frame closes the tunnel to avoid leaving the peer in a broken fragmented-message or closing state. Pending payload previews are available only to the paired local workbench while a frame is waiting; frame history remains metadata-only. This is an initial frame-level interception implementation, not complete WebSocket protocol tooling: fragmented binary-message editing, extension negotiation, HTTP/2 WebSockets and broad browser compatibility are not supported. WebSocket upgrades are rejected while manual HTTP request or response interception is enabled. It has not yet been verified against a full browser matrix. The proxy forwards in-scope browser traffic while enabled; use a dedicated test browser profile and stop it when finished. State-changing methods remain blocked by default. Manual request and response interception are disabled by default and each requires separate approval at proxy start.

## Not yet implemented

The crawler is a discovery and baseline layer, not a full active vulnerability scanner. The following native capabilities remain separate implementation work:
- Advanced interception features remain in development: binary and oversized response editing, response diff tooling, multi-origin profiles, HTTP/2, fragmented binary-message editing, extension negotiation, client-certificate authentication and broader browser compatibility.
- Authenticated crawling and session/role handling.
- Advanced vulnerability checks for SQL injection, SSRF, IDOR, authentication/session weaknesses and deeper API testing.
- Raw binary request/response editing and richer response-diff tooling.
- Bounded parameter mutation and fuzzing engine.
- WebSocket and GraphQL security testing.
- Full AI specialist-agent orchestration across crawl, scan, independent finding verification and reporting. The Agent Console currently provides a user-approved handoff and evidence-analysis step only.

These capabilities must not be represented as complete until implemented and tested against intentionally vulnerable local labs. Public targets require explicit written authorisation and a defined scope.

## Native parameter mutation planner (offline draft generation)

The companion's `parameter_lab.py` module provides a bounded parameter inventory and mutation-draft generator. It:
- Parses URL query parameters and URL-encoded form bodies only; JSON and multipart bodies are not parsed.
- Excludes parameter names that look like credentials, tokens, session identifiers, CSRF values, signatures or nonces.
- Generates at most 25 cases per operation, with one selected parameter changed per case and at most 512 characters per supplied value.
- Preserves other parameters and the operator-selected HTTP method. Form-body mutation requires POST, PUT or PATCH.
- Performs no network activity and marks every generated case as unsent. The generated objects are drafts for review and manual entry into the native Repeater; they are not automatically dispatched.
- Does not bypass Repeater's target confirmation, written-authorisation reference, state-change approval, DNS pinning or request limits.

This is a parameter-test planning foundation, not a full Intruder equivalent. The native Repeater now exposes parameter inspection, bounded case generation and a one-click handoff into unsent request tabs. It does not yet provide payload wordlists, concurrent execution, automatic response anomaly scoring or evidence reporting. Each request must remain individually reviewed and explicitly sent.


## Offline response-difference analysis

The paired companion exposes `POST /web/parameters/analyze` for two responses already captured by explicit Repeater sends. It compares status, body digest, body length, response timing and response headers. Sensitive header values (authorization, cookies, token-like headers) are redacted before any difference is returned. The analysis is offline: it does not issue requests, retain response bodies or create an exploitability verdict. Timing differences are advisory and should be repeated under comparable conditions. The Repeater's comparison panel can submit the selected in-session responses to this analyser and display the resulting review indicators.


## Chunked HTTP request handling

The native HTTP/1.1 proxy accepts a single `Transfer-Encoding: chunked` request body when no `Content-Length` is present. It decodes chunks within the existing 64 KB request-body limit, bounds chunk-line and trailer overhead, validates trailer syntax, and rejects framing, routing, authentication, conditional and payload-processing fields in trailers. The decoded body is forwarded upstream with a generated `Content-Length`; hop-by-hop transfer coding and trailers are not forwarded. Ambiguous transfer-coding combinations, unsupported expectations and malformed/incomplete chunks are rejected. Chunked upstream responses are decoded by the HTTP client, buffered within the existing 2 MB response limit, and reframed with a generated `Content-Length`; raw chunk framing and trailers are not forwarded. Gzip- and zlib-wrapped deflate-encoded upstream responses are decompressed under the same 2 MB output cap for inspection and browser delivery, with content-encoding, integrity digests, validators and range metadata removed after transformation. Other content encodings, stacked encodings and raw-deflate variants remain opaque and are not decoded. Chunked upstream responses are decoded by the HTTP client and reframed with a generated Content-Length after bounded buffering; raw chunk framing and trailers are not exposed to the browser.
