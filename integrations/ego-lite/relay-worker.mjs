#!/usr/bin/env node
/**
 * Outbound-only desktop relay worker. It accepts one typed action:
 * desktop.browser.inspect. It never executes job-supplied JavaScript.
 */
import { spawn } from "node:child_process";

const relayUrl = (process.env.CYBERLAB_RELAY_URL || "").replace(/\/$/, "");
const deviceToken = process.env.CYBERLAB_DEVICE_TOKEN || "";
const pollMs = Math.max(2000, Math.min(30000, Number(process.env.CYBERLAB_RELAY_POLL_MS || 4000)));

async function api(path, method = "GET", body) {
  const response = await fetch(relayUrl + path, {
    method,
    headers: {
      Authorization: "Bearer " + deviceToken,
      Accept: "application/json",
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(25000),
  });
  const text = await response.text();
  if (!response.ok) throw new Error("Relay HTTP " + response.status + ": " + text.slice(0, 500));
  const parsed = JSON.parse(text);
  if (!parsed || typeof parsed !== "object") throw new Error("Invalid relay response.");
  return parsed;
}

function validateInspectPayload(payload) {
  if (!payload || Object.keys(payload).sort().join(",") !== "allowed_origins,url") {
    throw new Error("Unexpected browser inspection payload.");
  }
  const target = new URL(payload.url);
  if (target.protocol !== "https:" || target.username || target.password) {
    throw new Error("Only HTTPS browser targets without embedded credentials are accepted.");
  }
  if (!Array.isArray(payload.allowed_origins) || !payload.allowed_origins.includes(target.origin)) {
    throw new Error("Target origin is not in the approved scope.");
  }
  return target;
}

function runEgoBrowser(script) {
  return new Promise((resolve, reject) => {
    const child = spawn("ego-browser", ["nodejs"], { shell: false, windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      if (error) reject(error); else resolve(value);
    };
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", chunk => { stdout = (stdout + chunk).slice(-60000); });
    child.stderr.on("data", chunk => { stderr = (stderr + chunk).slice(-8000); });
    child.on("error", error => finish(error));
    child.on("close", code => code === 0
      ? finish(null, { output: stdout, stderr, exitCode: code })
      : finish(new Error("ego-browser exited " + code + ": " + stderr.slice(-1500))));
    child.stdin.end(script);
    setTimeout(() => {
      if (!settled) {
        child.kill();
        finish(new Error("ego-browser inspection timed out after 60 seconds."));
      }
    }, 60000).unref();
  });
}

async function dispatch(job) {
  if (job.action !== "desktop.browser.inspect") throw new Error("Unsupported desktop relay action.");
  const target = validateInspectPayload(job.payload);
  // URL is JSON-encoded into a fixed script template. No job-supplied code is evaluated.
  const urlLiteral = JSON.stringify(target.href);
  const script = [
    'const task = await taskSpace("CyberLab authorised inspection");',
    'const page = task.page("p1");',
    'await page.goto(' + urlLiteral + ');',
    'const snapshot = await page.snapshot();',
    'console.log(JSON.stringify({integration:"ego(lite)",mode:"read-only",origin:' + JSON.stringify(target.origin) + ',snapshot}));',
    'await task.finish({keep:["p1"]});',
  ].join("\n");
  return await runEgoBrowser(script);
}

async function main() {
  if (!relayUrl.startsWith("https://") || deviceToken.length < 32) {
    throw new Error("Set HTTPS CYBERLAB_RELAY_URL and a paired CYBERLAB_DEVICE_TOKEN.");
  }
  console.log("CyberLab Ego Lite relay worker started; outbound HTTPS polling only.");
  for (;;) {
    try {
      const next = await api("/v1/jobs/next");
      if (!next.job) {
        await new Promise(resolve => setTimeout(resolve, pollMs));
        continue;
      }
      const job = next.job;
      let submission;
      try {
        const result = await dispatch(job);
        submission = { lease_token: job.lease_token, status: "completed", result, error: "" };
      } catch (error) {
        submission = { lease_token: job.lease_token, status: "failed", result: {}, error: String(error).slice(0, 1000) };
      }
      await api("/v1/jobs/" + encodeURIComponent(job.job_id) + "/result", "POST", submission);
      console.log("Job " + job.job_id + " -> " + submission.status + " (" + job.action + ")");
    } catch (error) {
      console.error("Relay error:", String(error).slice(0, 500));
      await new Promise(resolve => setTimeout(resolve, pollMs));
    }
  }
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
