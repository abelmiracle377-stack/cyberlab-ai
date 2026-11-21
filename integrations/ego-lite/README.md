# ego(lite) desktop browser integration

This directory adds the first executable CyberLab integration point for ego(lite): a local, read-only browser smoke test and an operator skill for a compatible desktop agent.

## Why this is a separate desktop component

ego(lite) is a desktop Chromium browser controlled through its local `ego-browser` runtime and agent skill. It is not a Chrome extension and it does not attach to an existing Chrome tab. The agent command must execute on the same desktop where ego(lite) is installed.

Install ego(lite) on the supported desktop host, finish onboarding, and verify that `ego-browser` is available in a local agent terminal. Linux is not currently a supported ego(lite) host; keep the Kali companion on the separate Kali machine.

## Run the smoke test

1. Install ego(lite) on the Windows/macOS desktop and complete onboarding.
2. Install a compatible local agent harness and load `integrations/ego-lite/SKILL.md` as a local skill.
3. Copy `inspect.mjs` to a local path.
4. Replace `https://example.com` with the exact operator-approved target.
5. Run:

   ```bash
   ego-browser nodejs < /absolute/path/to/inspect.mjs
   ```

6. Review the resulting snapshot in the agent output and the ego(lite) task Space.

This is a genuine browser-runtime smoke test, not a mock screenshot. It only navigates and reads the browser's supported page snapshot.

## Current integration boundary

- Implemented here: local ego-browser invocation pattern, task Space creation, navigation, snapshot capture, operator workflow and safety instructions.
- Existing in CyberLab: Chrome extension workspace and loopback Kali companion.
- Not yet implemented: a persistent CyberLab desktop companion service, secure cross-machine job relay between the desktop and separate Kali host, a unified browser/Kali execution queue, or automatic findings ingestion into the CyberLab case ledger.
- Not claimed: full DevTools parity, raw cookie export, authenticated request replay, automated XSS/SQLi verification, or a deployed Ego Lite connection.

The Kali bridge currently binds to `127.0.0.1`. Do not expose it directly to the internet or change it to bind to all interfaces. A separate desktop cannot call that loopback endpoint on the Kali machine. The next integration stage must use an authenticated outbound device channel with typed, allow-listed jobs and result receipts; it must not tunnel arbitrary shell commands.

## Local model privacy

ego(lite) page snapshots are processed by whichever model/provider the local agent harness is configured to use. For private assessment data, configure a local model provider and verify the actual network path before use. The Kali companion already has a loopback-only Ollama integration; it is not remotely exposed to the desktop. Do not expose Ollama port 11434 publicly or send raw session credentials to a hosted model.

## Outbound CyberLab relay worker

A desktop worker is now included at `relay-worker.mjs`. It polls the paired gateway over HTTPS and accepts only the typed `desktop.browser.inspect` action. It invokes the local `ego-browser nodejs` executable with a fixed snapshot script; job payloads cannot supply JavaScript or executable arguments.

After pairing the desktop in CyberLab's admin console at `/execution-relay`, set `CYBERLAB_RELAY_URL` and `CYBERLAB_DEVICE_TOKEN` in the desktop user's private environment, then run:

```bash
node integrations/ego-lite/relay-worker.mjs
```

The browser worker is outbound-only. It does not expose a local HTTP listener. Its current browser task is read-only navigation plus a page snapshot. It does not inspect/export cookies, submit forms, or run XSS/SQL injection payloads. Results are returned to the gateway as bounded execution receipts. Use an authorised test account and avoid pages containing unrelated personal or confidential data.
