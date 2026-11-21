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
