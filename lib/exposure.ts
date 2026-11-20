// External attack-surface assessment: turn a Shodan host result into CyberSOC
// alerts. Pure and dependency-light so it runs client-side (the Shodan query
// goes through the companion) and is unit-tested offline.

import type { Severity } from "./soc";

export type ShodanHost = {
  ip?: string; org?: string; os?: string; country?: string;
  ports?: number[];
  services?: { port?: number; product?: string; version?: string; transport?: string }[];
  vulns?: string[];
};

export type ExposureFinding = {
  key: string; title: string; severity: Severity;
  port?: number; cve?: string; detail: string; recommendation: string;
};

const SEVERITY_SCORE: Record<Severity, number> = {
  informational: 10, low: 30, medium: 55, high: 78, critical: 95,
};

// Services that should essentially never face the public internet.
const RISKY_PORTS: Record<number, { service: string; severity: Severity; reason: string }> = {
  23: { service: "Telnet", severity: "critical", reason: "Telnet is unencrypted; credentials cross the wire in cleartext." },
  2375: { service: "Docker API", severity: "critical", reason: "An unauthenticated Docker API grants remote code execution." },
  21: { service: "FTP", severity: "high", reason: "FTP is frequently unencrypted and anonymously accessible." },
  3389: { service: "RDP", severity: "high", reason: "Exposed RDP is a leading ransomware entry vector." },
  445: { service: "SMB", severity: "high", reason: "Exposed SMB is a wormable, high-risk surface." },
  3306: { service: "MySQL", severity: "high", reason: "Databases must not be internet-exposed." },
  5432: { service: "PostgreSQL", severity: "high", reason: "Databases must not be internet-exposed." },
  27017: { service: "MongoDB", severity: "high", reason: "Exposed MongoDB has caused mass data leaks." },
  6379: { service: "Redis", severity: "high", reason: "Exposed Redis is commonly unauthenticated." },
  9200: { service: "Elasticsearch", severity: "high", reason: "Exposed Elasticsearch has leaked large datasets." },
  5900: { service: "VNC", severity: "high", reason: "Exposed VNC often lacks strong authentication." },
  11211: { service: "memcached", severity: "medium", reason: "Exposed memcached enables DDoS amplification and data exposure." },
};

export function assessExposure(host: ShodanHost): ExposureFinding[] {
  const ip = host.ip || "unknown";
  const findings: ExposureFinding[] = [];
  const ports = Array.isArray(host.ports) ? host.ports : [];

  for (const port of ports) {
    const risk = RISKY_PORTS[port];
    if (risk) {
      findings.push({
        key: `${ip}:port:${port}`,
        title: `${risk.service} exposed on port ${port}`,
        severity: risk.severity, port,
        detail: `${risk.service} is reachable from the internet on ${ip}:${port}. ${risk.reason}`,
        recommendation: `Firewall or VPN-gate port ${port}; expose it only to trusted networks.`,
      });
    }
  }

  for (const cve of Array.isArray(host.vulns) ? host.vulns : []) {
    if (typeof cve !== "string" || !cve) continue;
    findings.push({
      key: `${ip}:cve:${cve}`,
      title: `Known vulnerability ${cve} on ${ip}`,
      severity: "high", cve,
      detail: `Shodan reports ${ip} as affected by ${cve}. Confirm and remediate; a public-facing known-vulnerable service is a direct entry point.`,
      recommendation: `Apply the vendor patch for ${cve} or take the affected service offline until patched.`,
    });
  }

  // If nothing risky stood out but services are exposed, record an informational surface note.
  if (findings.length === 0 && ports.length > 0) {
    findings.push({
      key: `${ip}:surface`,
      title: `${ports.length} service(s) exposed on ${ip}`,
      severity: "informational",
      detail: `${ip} exposes ports ${ports.slice(0, 20).join(", ")}. No high-risk service or known CVE was flagged, but review whether each needs to be public.`,
      recommendation: "Minimise the external surface: close ports that don't need to be internet-facing.",
    });
  }
  return findings;
}

// Map exposure findings to the raw alert shape accepted by POST /api/soc/alerts
// (normalizeIngestAlert), so they flow through the existing console.
export function exposureAlerts(host: ShodanHost): Record<string, unknown>[] {
  const ip = host.ip || "unknown";
  return assessExposure(host).map((f) => {
    const mitre = f.cve
      ? { tactic: "initial-access", technique_id: "T1190", technique: "Exploit Public-Facing Application" }
      : { tactic: "initial-access", technique_id: "T1133", technique: "External Remote Services" };
    const action = f.cve
      ? { action: "patch", rationale: `Apply the vendor patch for ${f.cve}.` }
      : { action: "restrict_exposure", rationale: f.recommendation };
    return {
      id: `exposure:${f.key}`,
      rule: "external_exposure",
      title: f.title,
      severity: f.severity,
      score: SEVERITY_SCORE[f.severity],
      mitre,
      description: f.detail,
      entities: { host: ip, src_ip: ip, org: host.org, port: f.port, cve: f.cve },
      recommended_actions: [action],
      source: "shodan",
    };
  });
}
