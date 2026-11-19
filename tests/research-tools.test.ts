import { test } from "node:test";
import assert from "node:assert/strict";
import { extractSubdomains } from "../lib/subdomain-extract";

test("extracts unique in-scope subdomains from crt.sh rows", () => {
  const rows = [
    { name_value: "www.example.com\napi.example.com" },
    { name_value: "*.example.com" },
    { name_value: "api.example.com" },            // duplicate
    { name_value: "mail.other.com" },             // out of scope
    { name_value: "example.com" },
  ];
  const subs = extractSubdomains(rows, "example.com");
  assert.deepEqual(subs, ["api.example.com", "example.com", "www.example.com"]);
});

test("strips wildcard prefixes and lowercases", () => {
  const subs = extractSubdomains([{ name_value: "*.Dev.Example.com" }], "example.com");
  assert.deepEqual(subs, ["dev.example.com"]);
});

test("returns empty for non-array or unrelated input", () => {
  assert.deepEqual(extractSubdomains(null, "example.com"), []);
  assert.deepEqual(extractSubdomains([{ name_value: "x.attacker.com" }], "example.com"), []);
});

test("does not treat a lookalike domain as in scope", () => {
  // notexample.com must not match example.com
  const subs = extractSubdomains([{ name_value: "a.notexample.com" }], "example.com");
  assert.deepEqual(subs, []);
});
