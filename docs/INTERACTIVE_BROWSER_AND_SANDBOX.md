# Interactive Browser Workspace and Independent Sandbox

CyberLab is gaining two execution environments that do not depend on Kali Companion or CyberLab AI OS.

## Shared browser workspace (initial release)

The browser-extension directory contains a Chrome Manifest V3 extension. It uses the Chrome DevTools Protocol through the browser's debugger permission after the user explicitly clicks **Inspect active tab with CyberLab**.

### Install and use

1. Download or clone this repository.
2. Open chrome://extensions in Chrome or a Chromium-based browser.
3. Enable Developer mode and choose **Load unpacked**.
4. Select the repository's browser-extension directory.
5. Sign in to CyberLab and open /browser-workspace.
6. Open the target web application in another tab, then click the CyberLab extension and choose **Inspect active tab with CyberLab**.

The extension sends a sanitised snapshot to the CyberLab browser workspace. The first release captures:
- Page title, origin, bounded DOM element metadata and form field names/types.
- Cookie names and security metadata for the selected tab's host only (Secure, HttpOnly, SameSite, path and expiry).
- Network request/response metadata observed during the short inspection window.

It intentionally excludes cookie values, passwords, input values, request bodies, response bodies and URL query values. It does not submit forms, replay requests or execute arbitrary JavaScript. The DOM editor can temporarily change only class, title, aria-label or placeholder attributes; these changes exist only in the live page DOM and can be undone or discarded by stopping the session/reloading the page. Chrome displays a prominent debugger permission warning because the extension uses DevTools Protocol access.

**Current limitation:** the extension keeps an explicit shared-tab session open while the CyberLab workspace remains open. The operator can make temporary DOM attribute edits limited to class, title, aria-label and placeholder, then undo the last edit or stop sharing. The initial release does not execute arbitrary console JavaScript, edit request/response bodies, submit forms or provide full DevTools parity. Network metadata is captured only during a short initial window, not as a continuous full HAR stream.

Only share applications you own or have explicit permission to assess. The browser workspace is an analysis surface, not a bypass for authentication or bug-bounty scope.

### Local session-cookie capture and page interaction

The extension now offers a separate **Capture session cookies locally** action. It requires an explicit confirmation after a tab has been shared. Cookie values are retained only in volatile memory inside the extension service worker, scoped to the shared tab's host, and are not included in the browser snapshot or sent to the CyberLab web application. The popup includes a clear action. Closing/restarting the browser extension worker also discards this volatile capture. The current UI reports cookie names/count only; it does not export raw values.

The browser workspace also supports writing a supplied value into a selected non-sensitive input, textarea or select field. Password, hidden, file and submit inputs are blocked. The operation dispatches input/change events but does not submit the form. This is a live-page interaction, not a server-side website edit. Existing reversible DOM attribute editing remains available.

This is not yet a full authenticated request replay engine. Cookie capture is local-only; do not interpret it as permission to export session secrets or use them outside the approved origin. The browser extension should be treated as a trusted local component and cleared after each engagement.

## Authorised SSH service audit

The Kali companion exposes `POST /ssh/audit`. It requires `authorized: true`, a non-empty authorisation reference, a single host and a port. It collects the SSH identification banner and invokes the locally installed `ssh-audit` executable when available to report cryptographic protocol posture. It never logs in, guesses passwords, enumerates users, collects private keys or validates credentials. Single private-network IPs are permitted for explicitly authorised internal assessments; loopback, link-local, multicast, unspecified and reserved addresses are blocked. Install the distribution's `ssh-audit` package on the paired Kali host to obtain algorithm-level results. Banner-only output is explicitly marked as limited evidence.

## Independent CyberLab sandbox

The sandbox has its own execution service and disposable container image. It does not invoke the Kali companion or require CyberLab AI OS.

### Architecture

- sandbox/runner.py: small authenticated service that accepts bounded Python, JavaScript or shell source and launches a disposable container.
- sandbox/Dockerfile: minimal runtime image.
- app/api/sandbox/run/route.ts: authenticated Next.js proxy; requires a signed-in Supabase user and keeps the runner token server-side.
- app/sandbox/page.tsx: browser-based code runner interface.

Each job runs under the gVisor (runsc) runtime with networking disabled, read-only container root, no Linux capabilities, no-new-privileges, a non-root UID, 384 MiB memory, one CPU, 64 process limit, a 20-second runtime limit, bounded output and a maximum of two concurrent jobs. The submitted source is mounted read-only into the container. No host home directory, Docker socket, credentials or companion files are mounted into the job.

### Deploy the runner on a dedicated Linux VM

This is separate infrastructure—not the CyberLab OS and not the Kali companion. Put it behind HTTPS and a reverse proxy; do not expose port 8787 directly to the public internet.

```bash
cd sandbox
docker build -t cyberlab-sandbox:latest -f Dockerfile .
export CYBERLAB_SANDBOX_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
export CYBERLAB_SANDBOX_BIND="127.0.0.1"
python3 runner.py
```

Configure these server-side Vercel environment variables for the CyberLab project:
- CYBERLAB_SANDBOX_URL: the HTTPS base URL of the dedicated runner service.
- CYBERLAB_SANDBOX_TOKEN: the same high-entropy token used by the runner.

Redeploy the web application after configuring the variables. Install and configure Docker Engine plus the gVisor runsc runtime on the dedicated host before starting the runner. The runner service must be able to access the local Docker daemon and the cyberlab-sandbox:latest image. Keep both runtimes patched and isolate this host from production secrets. The API binds to loopback by default; terminate TLS at a reverse proxy and forward only to 127.0.0.1:8787.

### Current sandbox limits

The initial runner is a code-execution foundation. It does not yet provide persistent project files, a graphical browser, outbound network testing, Kali tools, package installation, multi-container labs, snapshots or long-running job queues. Network access is disabled by design. Future browser-based XSS/SQLi practice should use disposable, deliberately vulnerable targets on a separate isolated lab network—not enable arbitrary internet access for untrusted code.

## Next implementation stages

1. Persistent browser share sessions with a visible sharing indicator, live network metadata and safe, reversible DOM edits.
2. Explicit approval gates for console commands, request replay, form submission and active tests.
3. Persistent sandbox projects, file tree/editor, terminal sessions, job queue and snapshots.
4. Browser automation connected to disposable training targets (OWASP Juice Shop, WebGoat and custom CyberLab Academy labs).
5. Isolated network profiles with per-target allowlists for authorised assessment labs.
6. Unified agent tool orchestration so specialist agents can delegate to the browser workspace or sandbox, observe execution and validate evidence.


## ego(lite) desktop browser integration

The `integrations/ego-lite/` directory contains a local operator skill and an executable read-only smoke test for the official `ego-browser` runtime. ego(lite) runs on the supported desktop host (Windows/macOS), uses its own task Space, and does not attach to an existing Chrome tab. Run the smoke test on the same desktop where ego(lite) is installed:

```bash
ego-browser nodejs < /absolute/path/to/inspect.mjs
```

Edit the example URL in `inspect.mjs` only after confirming the operator's authorised target. The script navigates and captures a supported page snapshot; it does not extract credentials or execute vulnerability payloads. See `integrations/ego-lite/README.md` for setup and current boundaries.

**Cross-machine limitation:** the existing Kali bridge binds to loopback. A separate desktop cannot reach the Kali machine's `127.0.0.1` service. The current VPS gateway pairs devices for its existing permissions/files workflow but does not yet relay CyberLab tool jobs. A secure outbound typed-job relay and unified browser/Kali queue remain required before CyberLab can orchestrate both machines automatically. Do not expose the Kali bridge or Ollama directly to the public internet.



## Separate Kali + ego(lite) cross-machine execution relay

The personal gateway now provides an authenticated typed job queue at `/v1/jobs`. Kali and the ego(lite) desktop each run an outbound polling worker; neither device opens an inbound public port. The queue supports read-only Kali health/tool/Ollama inventory, the existing registered Kali tool runner, and read-only ego(lite) page snapshots. Each queued job requires an owner-authenticated request, an explicit operator approval flag, a reference, a device-specific token, and a short-lived lease. Results are capped and stored as execution receipts.

CyberLab exposes an administrator-only console at `/execution-relay` and server API routes under `/api/relay`. Set server-only `CYBERLAB_GATEWAY_URL` and `CYBERLAB_GATEWAY_OWNER_TOKEN` in Vercel. The existing Supabase admin gate protects pairing, queueing, result review and cancellation. The gateway itself must run behind TLS; its application service remains bound to loopback.

The desktop worker is `integrations/ego-lite/relay-worker.mjs`; the Kali worker is `kali-companion/relay_worker.py`. Read `kali-companion/README.md` for pairing and start-up instructions. A running Kali job cannot be forcibly interrupted by the relay; cancellation is offered only before a job is claimed. Expired leases can be reclaimed by the device worker.

This stage connects the two execution machines but is not a complete autonomous vulnerability-testing engine. Ego Lite currently returns a read-only snapshot; Kali executes only the existing registered tool runner with its own validation. Full browser XSS/SQLi testing, authenticated request replay, unified case-ledger ingestion and local model orchestration across machines remain future implementation stages. Never expose the Kali bridge or Ollama port directly to the internet.

The relay also supports a bounded `kali.ollama.chat` task that forwards a model tag and prompt to the local Kali bridge's Ollama adapter. Model inference remains on Kali; this is not yet a tool-using autonomous loop. Keep Ollama bound to loopback and never expose port 11434 publicly.
