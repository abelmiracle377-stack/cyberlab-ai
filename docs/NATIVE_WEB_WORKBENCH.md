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
- Optional manual interception pauses each request in a bounded in-memory queue (20 requests maximum). The operator explicitly forwards or drops each request; undecided requests are dropped after 120 seconds, and stopping the proxy drops all pending requests. The queue displays redacted headers and body length only; it does not expose or retain request bodies.
- Enforces that exact scheme/host/port for every request and blocks other hosts, including cross-origin redirects when the browser follows them.
- Supports HTTP/1.1 absolute-form HTTP requests and HTTPS CONNECT with TLS termination using a CyberLab-issued exact-host certificate.
- Validates the upstream HTTPS certificate using the operating system's normal trust roots and pins the resolved address for each upstream connection.
- Forwards request and response bodies but never retains body contents in proxy history. History redacts credentials, cookies, token-like headers, redirect locations and URL query strings.
- Uses bounded header sizes, request bodies (64 KB), response bodies (2 MB) and network timeouts; oversized responses are rejected rather than partially relayed.
- Requires a local CA created by explicit approval. The operator must manually install the public CA certificate in a dedicated test browser profile; CyberLab never changes system/browser trust stores or exports the private key.

This is an initial HTTP/1.1 proxy, not full Burp parity. It handles one request per client connection and does not support HTTP/2, WebSockets, chunked client request bodies, client certificates, request pause/edit queues, or multi-origin scope profiles. It has not yet been verified against a full browser matrix. The proxy forwards in-scope browser traffic while enabled; use a dedicated test browser profile and stop it when finished. State-changing methods remain blocked by default. Manual request interception is disabled by default and requires separate approval at proxy start.

## Not yet implemented

The crawler is a discovery and baseline layer, not a full active vulnerability scanner. The following native capabilities remain separate implementation work:
- Advanced interception features remain in development: pause/edit/resume queues, multi-origin profiles, HTTP/2, WebSockets, chunked client request bodies, client-certificate authentication and broader browser compatibility.
- Authenticated crawling and session/role handling.
- Advanced vulnerability checks for SQL injection, SSRF, IDOR, authentication/session weaknesses and deeper API testing.
- Native request repeater UI with response comparison.
- Bounded parameter mutation and fuzzing engine.
- WebSocket and GraphQL security testing.
- Full AI specialist-agent orchestration across crawl, scan, independent finding verification and reporting. The Agent Console currently provides a user-approved handoff and evidence-analysis step only.

These capabilities must not be represented as complete until implemented and tested against intentionally vulnerable local labs. Public targets require explicit written authorisation and a defined scope.
