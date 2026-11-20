// SERVER-ONLY. Do NOT import this from a client component — it contains the lab
// flags. It is imported only by the /api/academy/lab/target route.
//
// A TypeScript twin of kali-companion/academy_lab.py (build_response), so the
// vulnerable target can be hosted inside the web app and attacked entirely in
// the browser ("only there"), with no local companion. Flags are identical to
// the Python lab, so progress grading and the scoreboard stay consistent across
// both paths.

const FLAGS = {
  recon: "CYBERLAB{recon_robots_txt}",
  env: "CYBERLAB{dotenv_secrets_exposed}",
  git: "CYBERLAB{git_source_leak}",
  header: "CYBERLAB{response_header_leak}",
  sqli: "CYBERLAB{error_based_sqli}",
  idor: "CYBERLAB{idor_order_access}",
  traversal: "CYBERLAB{path_traversal_secret}",
  authbypass: "CYBERLAB{cookie_role_forgery}",
  jwt: "CYBERLAB{jwt_alg_none}",
  ssrf: "CYBERLAB{ssrf_internal_metadata}",
};
export const HIDDEN_PATH = "/flag-7a1c";

export type LabRequest = { method?: string; path?: string; query?: string; headers?: Record<string, string> };
export type LabResponse = { status: number; headers: Record<string, string>; body: string };

const BASE_HTML =
  "<!doctype html><html><head><title>CyberLab Vulnerable Shop</title></head>" +
  "<body><h1>CyberLab Vulnerable Shop</h1>" +
  "<p>A deliberately insecure training target. Find the flags.</p>" +
  "<!-- hint: check /robots.txt, /.env, /.git/config, /api/status headers, and /product?id= -->" +
  "<ul><li><a href='/product?id=1'>Product 1</a></li></ul></body></html>";

function text(status: number, body: string, extra?: Record<string, string>): LabResponse {
  return { status, headers: { "Content-Type": "text/plain; charset=utf-8", ...(extra || {}) }, body };
}

function decodeJwt(token: string): { head: Record<string, unknown> | null; payload: Record<string, unknown> | null } {
  try {
    const parts = token.split(".");
    if (parts.length < 2) return { head: null, payload: null };
    const seg = (s: string) => JSON.parse(Buffer.from(s, "base64url").toString("utf-8"));
    return { head: seg(parts[0]), payload: seg(parts[1]) };
  } catch { return { head: null, payload: null }; }
}

export function handleLabRequest(req: LabRequest): LabResponse {
  const method = (req.method || "GET").toUpperCase();
  const path = req.path || "/";
  const params = new URLSearchParams(req.query || "");
  const hdr: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers || {})) hdr[k.toLowerCase()] = v;

  if (method !== "GET" && method !== "HEAD") return text(405, "Method Not Allowed");

  if (path === "/") return { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" }, body: BASE_HTML };
  if (path === "/robots.txt") return text(200, `User-agent: *\nDisallow: ${HIDDEN_PATH}\n`);
  if (path === HIDDEN_PATH) return text(200, `Nice recon. Flag: ${FLAGS.recon}\n`);
  if (path === "/.env") return text(200, `APP_ENV=production\nAPP_DEBUG=false\nDB_PASSWORD=hunter2\nFLAG=${FLAGS.env}\n`);
  if (path === "/.git/HEAD") return text(200, "ref: refs/heads/main\n");
  if (path === "/.git/config") return text(200, `[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = git@example.com:shop.git\n# flag: ${FLAGS.git}\n`);
  if (path === "/api/status") return { status: 200, headers: { "Content-Type": "application/json", "X-Flag": FLAGS.header }, body: JSON.stringify({ status: "ok" }) };

  if (path === "/product") {
    const id = params.get("id") || "";
    if (id.includes("'") || id.includes('"')) {
      return text(500, `SQL error: You have an error in your SQL syntax near '${id.slice(0, 40)}'. Debug flag: ${FLAGS.sqli}\n`);
    }
    return { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" }, body: `<html><body><h2>Product ${id.slice(0, 20) || "1"}</h2><p>In stock.</p></body></html>` };
  }

  if (path === "/api/orders") {
    const oid = params.get("id") ?? "1001";
    if (oid === "1001") return { status: 200, headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id: 1001, owner: "you", item: "Mug", total: 12 }) };
    if (oid === "1000") return { status: 200, headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id: 1000, owner: "victim", item: "Laptop", flag: FLAGS.idor }) };
    return text(404, "No such order");
  }

  if (path === "/download") {
    const fname = params.get("file") || "";
    if (fname.includes("..") && fname.toLowerCase().includes("flag")) return text(200, `Secret file contents. Flag: ${FLAGS.traversal}\n`);
    if (fname) return text(200, `Report: quarterly figures for ${fname.slice(0, 40)}\n`);
    return text(400, "Provide a file parameter, e.g. ?file=report.txt");
  }

  if (path === "/admin") {
    const cookie = (hdr["cookie"] || "").replace(/\s/g, "");
    if (cookie.includes("role=admin")) return text(200, `Admin dashboard. Flag: ${FLAGS.authbypass}\n`);
    return text(403, "Forbidden: admin role required.");
  }

  if (path === "/api/profile") {
    const auth = hdr["authorization"] || "";
    const token = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : "";
    const { head, payload } = decodeJwt(token);
    if (head && payload && String(head["alg"] || "").toLowerCase() === "none" && (payload["role"] === "admin" || payload["admin"] === true)) {
      return { status: 200, headers: { "Content-Type": "application/json" }, body: JSON.stringify({ role: "admin", flag: FLAGS.jwt }) };
    }
    return text(401, "Unauthorized: valid admin token required.");
  }

  if (path === "/fetch") {
    const target = (params.get("url") || "").toLowerCase();
    const internal = ["169.254.169.254", "127.0.0.1", "localhost", "metadata.internal", "::1"];
    if (target && internal.some((h) => target.includes(h))) return text(200, `Internal metadata response (simulated). Flag: ${FLAGS.ssrf}\n`);
    if (target) return text(200, "Fetched external URL (allowed).");
    return text(400, "Provide a url parameter.");
  }

  return text(404, "Not Found");
}

export const LAB_CHALLENGES = [
  { id: "recon", tier: 1, points: 10, title: "Robots recon", technique: "Read /robots.txt and follow the disallowed path.", preset: { path: "/robots.txt", query: "" } },
  { id: "dotenv", tier: 1, points: 10, title: "Exposed .env", technique: "The environment file is web-served.", preset: { path: "/.env", query: "" } },
  { id: "git", tier: 1, points: 10, title: "Exposed .git", technique: "The version-control folder is downloadable.", preset: { path: "/.git/config", query: "" } },
  { id: "header", tier: 1, points: 10, title: "Leaky response header", technique: "Read the X-Flag response header.", preset: { path: "/api/status", query: "" } },
  { id: "sqli", tier: 2, points: 20, title: "Error-based SQLi", technique: "Break the query with a single quote.", preset: { path: "/product", query: "id=1'" } },
  { id: "idor", tier: 2, points: 20, title: "IDOR on orders", technique: "Read another user's order id.", preset: { path: "/api/orders", query: "id=1000" } },
  { id: "traversal", tier: 2, points: 20, title: "Path traversal", technique: "Climb to the secret flag file.", preset: { path: "/download", query: "file=../../secret/flag.txt" } },
  { id: "authbypass", tier: 3, points: 30, title: "Cookie auth bypass", technique: "Forge Cookie: role=admin.", preset: { path: "/admin", query: "" } },
  { id: "jwt", tier: 3, points: 30, title: "JWT alg:none", technique: "Send an unsigned admin token.", preset: { path: "/api/profile", query: "" } },
  { id: "ssrf", tier: 3, points: 30, title: "SSRF to metadata", technique: "Target 169.254.169.254.", preset: { path: "/fetch", query: "url=http://169.254.169.254/latest/meta-data/" } },
];
