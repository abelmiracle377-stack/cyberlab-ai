import { test } from "node:test";
import assert from "node:assert/strict";
import { handleLabRequest, HIDDEN_PATH } from "../lib/academy-lab-target";

// Parity with the Python lab: these flag strings must match academy_lab.py and
// the CTF track answers in academy-content.ts.
const F = {
  recon: "CYBERLAB{recon_robots_txt}", env: "CYBERLAB{dotenv_secrets_exposed}",
  git: "CYBERLAB{git_source_leak}", header: "CYBERLAB{response_header_leak}",
  sqli: "CYBERLAB{error_based_sqli}", idor: "CYBERLAB{idor_order_access}",
  traversal: "CYBERLAB{path_traversal_secret}", authbypass: "CYBERLAB{cookie_role_forgery}",
  jwt: "CYBERLAB{jwt_alg_none}", ssrf: "CYBERLAB{ssrf_internal_metadata}",
};
const b64url = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");

test("tier 1: recon, env, git, header", () => {
  assert.ok(handleLabRequest({ path: "/robots.txt" }).body.includes(HIDDEN_PATH));
  assert.ok(handleLabRequest({ path: HIDDEN_PATH }).body.includes(F.recon));
  assert.ok(handleLabRequest({ path: "/.env" }).body.includes(F.env));
  assert.ok(handleLabRequest({ path: "/.git/config" }).body.includes(F.git));
  assert.equal(handleLabRequest({ path: "/api/status" }).headers["X-Flag"], F.header);
});

test("tier 2: sqli, idor, traversal", () => {
  assert.ok(!handleLabRequest({ path: "/product", query: "id=1" }).body.includes(F.sqli));
  assert.ok(handleLabRequest({ path: "/product", query: "id=1'" }).body.includes(F.sqli));
  assert.ok(!handleLabRequest({ path: "/api/orders", query: "id=1001" }).body.includes(F.idor));
  assert.ok(handleLabRequest({ path: "/api/orders", query: "id=1000" }).body.includes(F.idor));
  assert.ok(!handleLabRequest({ path: "/download", query: "file=report.txt" }).body.includes(F.traversal));
  assert.ok(handleLabRequest({ path: "/download", query: "file=../../secret/flag.txt" }).body.includes(F.traversal));
});

test("tier 3: auth bypass, jwt alg:none, ssrf", () => {
  assert.equal(handleLabRequest({ path: "/admin" }).status, 403);
  assert.ok(handleLabRequest({ path: "/admin", headers: { Cookie: "session=x; role=admin" } }).body.includes(F.authbypass));

  const token = b64url({ alg: "none", typ: "JWT" }) + "." + b64url({ role: "admin" }) + ".";
  assert.ok(handleLabRequest({ path: "/api/profile", headers: { Authorization: "Bearer " + token } }).body.includes(F.jwt));
  const signed = b64url({ alg: "HS256" }) + "." + b64url({ role: "admin" }) + ".sig";
  assert.equal(handleLabRequest({ path: "/api/profile", headers: { Authorization: "Bearer " + signed } }).status, 401);

  assert.ok(!handleLabRequest({ path: "/fetch", query: "url=https://example.com" }).body.includes(F.ssrf));
  assert.ok(handleLabRequest({ path: "/fetch", query: "url=http://169.254.169.254/latest/meta-data/" }).body.includes(F.ssrf));
});

test("unknown path 404, non-GET 405", () => {
  assert.equal(handleLabRequest({ path: "/nope" }).status, 404);
  assert.equal(handleLabRequest({ method: "POST", path: "/" }).status, 405);
});
