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

The native HTTP workbench can load an in-memory request-history item back into the editor for an explicitly approved replay. History retains safe request-header metadata, redacts Authorization/Cookie/API-key/token headers and does not retain request-body contents. If the original request had a body, the UI tells the operator to re-enter it. Loading a history item never sends it automatically; scope and send approval are required again.

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

## Not yet implemented

The crawler is a discovery and baseline layer, not a full active vulnerability scanner. The following native capabilities remain separate implementation work:
- Intercepting HTTP/HTTPS proxy with a user-managed local CA and browser integration.
- Authenticated crawling and session/role handling.
- Advanced vulnerability checks for SQL injection, SSRF, IDOR, authentication/session weaknesses and deeper API testing.
- Native request repeater UI with response comparison.
- Bounded parameter mutation and fuzzing engine.
- WebSocket and GraphQL security testing.
- AI specialist-agent orchestration across crawl, scan, verification and reporting.

These capabilities must not be represented as complete until implemented and tested against intentionally vulnerable local labs. Public targets require explicit written authorisation and a defined scope.
