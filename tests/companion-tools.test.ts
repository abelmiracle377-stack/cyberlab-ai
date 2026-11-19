import { test } from "node:test";
import assert from "node:assert/strict";
import { planCompanionToolRequest } from "../lib/companion-tools";

test("plans a whois lookup from a passive instruction", () => {
  const req = planCompanionToolRequest("run whois on example.com");
  assert.equal(req?.tool, "whois");
  assert.equal(req?.active, false);
  assert.equal(req?.parameters.host, "example.com");
  assert.deepEqual(req?.missing, []);
});

test("plans a dnsrecon lookup", () => {
  const req = planCompanionToolRequest("do a dns recon of example.org");
  assert.equal(req?.tool, "dnsrecon");
  assert.equal(req?.parameters.host, "example.org");
});

test("plans an active whatweb run and marks it active", () => {
  const req = planCompanionToolRequest("whatweb https://target.example.com/login");
  assert.equal(req?.tool, "whatweb");
  assert.equal(req?.active, true);
  assert.equal(req?.targetParam, "url");
  assert.equal(req?.parameters.url, "https://target.example.com/login");
});

test("plans a nikto web server scan", () => {
  const req = planCompanionToolRequest("run a web server scan with nikto on https://app.example.com");
  assert.equal(req?.tool, "nikto");
  assert.equal(req?.active, true);
});

test("gobuster with a wordlist has nothing missing", () => {
  const req = planCompanionToolRequest("gobuster https://example.com using /usr/share/wordlists/common.txt");
  assert.equal(req?.tool, "gobuster-dir");
  assert.equal(req?.parameters.wordlist, "/usr/share/wordlists/common.txt");
  assert.deepEqual(req?.missing, []);
});

test("gobuster without a wordlist reports it as missing", () => {
  const req = planCompanionToolRequest("directory discovery on https://example.com with gobuster");
  assert.equal(req?.tool, "gobuster-dir");
  assert.deepEqual(req?.missing, ["wordlist"]);
});

test("extracts host from a URL for whois", () => {
  const req = planCompanionToolRequest("whois https://sub.example.co.uk/path");
  assert.equal(req?.parameters.host, "sub.example.co.uk");
});

test("returns null for ordinary chat with no tool intent", () => {
  assert.equal(planCompanionToolRequest("explain how TLS certificate validation works"), null);
  assert.equal(planCompanionToolRequest("what is an IP address?"), null);
});

test("returns null when a tool is named but no target is present", () => {
  assert.equal(planCompanionToolRequest("what does whatweb do?"), null);
});
