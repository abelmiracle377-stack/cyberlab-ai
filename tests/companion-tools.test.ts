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

test("plans a sqlmap run", () => {
  const req = planCompanionToolRequest("test for sql injection on https://example.com/item?id=1");
  assert.equal(req?.tool, "sqlmap");
  assert.equal(req?.active, true);
});

test("plans a metasploit module search without a target", () => {
  const req = planCompanionToolRequest("search metasploit for CVE-2017-0144");
  assert.equal(req?.tool, "metasploit-search");
  assert.equal(req?.active, false);
  assert.equal(req?.parameters.query, "CVE-2017-0144");
});

test("plans a netcat banner grab with host and port", () => {
  const req = planCompanionToolRequest("netcat banner grab on example.com port 22");
  assert.equal(req?.tool, "netcat-banner");
  assert.equal(req?.parameters.host, "example.com");
  assert.equal(req?.parameters.port, 22);
});

test("plans an sslscan TLS review", () => {
  const req = planCompanionToolRequest("run sslscan on example.com");
  assert.equal(req?.tool, "sslscan");
  assert.equal(req?.active, true);
});

test("plans a masscan with default ports", () => {
  const req = planCompanionToolRequest("masscan 93.184.216.34");
  assert.equal(req?.tool, "masscan");
  assert.equal(req?.parameters.rate, 1000);
});

test("plans wpscan, nuclei and wafw00f for URLs", () => {
  assert.equal(planCompanionToolRequest("wpscan https://blog.example.com")?.tool, "wpscan");
  assert.equal(planCompanionToolRequest("run nuclei on https://example.com")?.tool, "nuclei");
  assert.equal(planCompanionToolRequest("detect waf on https://example.com")?.tool, "wafw00f");
});

test("plans SMB/SSH enumeration for hosts", () => {
  assert.equal(planCompanionToolRequest("enum4linux 10.0.0.5")?.tool, "enum4linux-ng");
  assert.equal(planCompanionToolRequest("smbmap 10.0.0.5")?.tool, "smbmap");
  assert.equal(planCompanionToolRequest("ssh-audit example.com")?.tool, "ssh-audit");
});

test("plans passive subdomain and OSINT recon", () => {
  assert.equal(planCompanionToolRequest("find subdomains of example.com")?.tool, "sublist3r");
  assert.equal(planCompanionToolRequest("theharvester example.com")?.tool, "theharvester");
  assert.equal(planCompanionToolRequest("dnsenum example.com")?.active, false);
});

test("ffuf without wordlist reports it missing", () => {
  const req = planCompanionToolRequest("ffuf https://example.com");
  assert.equal(req?.tool, "ffuf");
  assert.deepEqual(req?.missing, ["wordlist"]);
});

test("returns null for ordinary chat with no tool intent", () => {
  assert.equal(planCompanionToolRequest("explain how TLS certificate validation works"), null);
  assert.equal(planCompanionToolRequest("what is an IP address?"), null);
});

test("returns null when a tool is named but no target is present", () => {
  assert.equal(planCompanionToolRequest("what does whatweb do?"), null);
});
