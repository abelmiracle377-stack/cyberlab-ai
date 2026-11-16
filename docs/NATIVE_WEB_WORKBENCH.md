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

## Not yet implemented

The crawler is a discovery and baseline layer, not a full active vulnerability scanner. The following native capabilities remain separate implementation work:
- Intercepting HTTP/HTTPS proxy with a user-managed local CA and browser integration.
- Authenticated crawling and session/role handling.
- Active, non-destructive vulnerability probes with per-check approval and evidence verification.
- Native request repeater UI with response comparison.
- Bounded parameter mutation and fuzzing engine.
- WebSocket and GraphQL security testing.
- AI specialist-agent orchestration across crawl, scan, verification and reporting.

These capabilities must not be represented as complete until implemented and tested against intentionally vulnerable local labs. Public targets require explicit written authorisation and a defined scope.
