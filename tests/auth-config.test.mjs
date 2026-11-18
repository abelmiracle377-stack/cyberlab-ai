import test from "node:test";
import assert from "node:assert/strict";
import { authConfigurationDecision, isPublicPath } from "../lib/auth-config.mjs";

test("known public routes remain reachable without Supabase configuration", () => {
  for (const path of ["/login", "/pricing", "/admin/login", "/auth/callback?code=x", "/api/paystack/webhook"]) {
    assert.equal(isPublicPath(path), true, path);
    assert.equal(authConfigurationDecision(path, false, false), "allow-public", path);
  }
});

test("protected pages fail closed when either Supabase setting is missing", () => {
  assert.equal(authConfigurationDecision("/", false, true), "unavailable");
  assert.equal(authConfigurationDecision("/dashboard", true, false), "unavailable");
  assert.equal(authConfigurationDecision("/learning", false, false), "unavailable");
});

test("protected API routes fail closed when Supabase configuration is missing", () => {
  assert.equal(authConfigurationDecision("/api/agent", false, false), "unavailable");
  assert.equal(authConfigurationDecision("/api/admin/users", false, true), "unavailable");
});

test("all paths proceed to normal auth checks when both settings exist", () => {
  assert.equal(authConfigurationDecision("/", true, true), "configured");
  assert.equal(authConfigurationDecision("/api/agent", true, true), "configured");
  assert.equal(authConfigurationDecision("/login", true, true), "configured");
});
