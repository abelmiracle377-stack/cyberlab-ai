export type Specialist = "recon" | "vulnerability-intelligence" | "malware-analysis" | "reverse-engineering" | "blue-team" | "reporting" | "general";

const profiles: Record<Specialist, { label: string; focus: string }> = {
  recon: { label: "Reconnaissance Analyst", focus: "Prioritise passive domain, IP, DNS, registration and certificate intelligence. Do not initiate active scans unless the dedicated approval workflow is used." },
  "vulnerability-intelligence": { label: "Vulnerability Intelligence Analyst", focus: "Prioritise CVE identifiers, CVSS context, affected-version verification, vendor advisories and remediation. A version match alone is not proof of exposure." },
  "malware-analysis": { label: "Malware Triage Analyst", focus: "Prioritise safe static triage, hashes, file format, entropy, strings and indicators. Never execute samples or recommend uploading private samples to third parties without consent." },
  "reverse-engineering": { label: "Reverse Engineering Analyst", focus: "Explain binary formats, headers, imports, disassembly concepts and supplied code. Keep analysis static unless an isolated lab workflow is explicitly configured." },
  "blue-team": { label: "Blue Team Analyst", focus: "Prioritise defensive detection, telemetry interpretation, incident triage, containment planning and MITRE ATT&CK mapping. Do not claim host monitoring is active unless a collector confirms it." },
  reporting: { label: "Evidence & Reporting Analyst", focus: "Structure findings with evidence, source, timestamp, scope, confidence, impact, limitations and actionable remediation." },
  general: { label: "Security Research Coordinator", focus: "Coordinate evidence-first cybersecurity research, identify which existing CyberLab tools are relevant, and state what is unknown." },
};

export function routeSpecialist(prompt: string) {
  const text = prompt.toLowerCase();
  let specialist: Specialist = "general";
  if (/\b(cve|cvss|vulnerab|exploitability|patch|advisory|kev|epss)\b/.test(text)) specialist = "vulnerability-intelligence";
  else if (/\b(malware|ransomware|trojan|sample|yara|hash|ioc|suspicious file)\b/.test(text)) specialist = "malware-analysis";
  else if (/\b(reverse engineer|disassembl|decompil|elf|pe file|mach-o|binary|firmware)\b/.test(text)) specialist = "reverse-engineering";
  else if (/\b(soc|incident|blue team|defend|mitre|att&ck|endpoint|telemetry|log analysis)\b/.test(text)) specialist = "blue-team";
  else if (/\b(report|executive summary|findings|evidence|write-up)\b/.test(text)) specialist = "reporting";
  else if (/\b(domain|dns|ip address|osint|subdomain|whois|certificate|recon|nmap|port scan)\b/.test(text)) specialist = "recon";
  const profile = profiles[specialist];
  return { specialist, label: profile.label, instructions: profile.focus };
}

export const specialistCatalogue = Object.entries(profiles).map(([id, profile]) => ({ id, name: profile.label, focus: profile.focus }));
