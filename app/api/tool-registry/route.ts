import { NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type State = "operational" | "configured" | "partial" | "requires-setup" | "planned";
const registry: Array<{ id:string; name:string; category:string; description:string; state:State; route:string; permission:"passive"|"local-approved"|"manual"; dependency?:string }> = [
 {id:"ai-agent",name:"AI Agent",category:"Orchestration",description:"Streaming model access with specialist routing and existing research tools.",state:"configured",route:"/agent",permission:"passive",dependency:"OPENROUTER_API_KEY"},
 {id:"ip-intelligence",name:"IP Intelligence",category:"Intelligence",description:"Public IP, ASN, ISP and approximate network context.",state:"operational",route:"/ip-intelligence",permission:"passive"},
 {id:"dns-intelligence",name:"DNS Intelligence",category:"Intelligence",description:"Passive A, AAAA, MX, NS and TXT resolution.",state:"operational",route:"/osint",permission:"passive"},
 {id:"rdap-ct",name:"Domain OSINT",category:"Intelligence",description:"Registration and certificate-transparency research.",state:"operational",route:"/osint",permission:"passive"},
 {id:"domain-posture",name:"Domain Security Posture",category:"Intelligence",description:"Passive SPF, DMARC, common DKIM selector, MX and CAA checks.",state:"operational",route:"/verification",permission:"passive"},
 {id:"historical-urls",name:"Historical URL Discovery",category:"Intelligence",description:"Public archived URL captures from Internet Archive CDX.",state:"operational",route:"/verification",permission:"passive"},
 {id:"browser-transparency",name:"Browser Fingerprint Transparency",category:"Verification",description:"Local-only inspection of browser attributes; no server upload.",state:"operational",route:"/verification",permission:"manual"},
 {id:"nvd",name:"NVD Vulnerability Research",category:"Intelligence",description:"Public CVE search and CVSS summaries.",state:"operational",route:"/vulnerability-lab",permission:"passive"},
 {id:"website-assessment",name:"Website Assessment",category:"Assessment",description:"Passive HTTP security headers, HTTPS and cookie review.",state:"operational",route:"/website-assessment",permission:"passive"},
 {id:"active-tcp",name:"Active Security Lab",category:"Assessment",description:"Bounded TCP reachability checks after explicit target and authorisation confirmation.",state:"configured",route:"/active-security-lab",permission:"local-approved"},
 {id:"kali-nmap",name:"Kali Nmap Bridge",category:"Assessment",description:"Local Nmap TCP service scan through paired companion.",state:"requires-setup",route:"/kali-connection",permission:"local-approved",dependency:"Paired local Kali companion"},
 {id:"nmap-parser",name:"Nmap XML Parser",category:"Analysis",description:"Import and interpret existing Nmap XML evidence.",state:"operational",route:"/network-analysis",permission:"manual"},
 {id:"malware-static",name:"Static Malware Triage",category:"Analysis",description:"Hash, file signature, entropy and selected string indicators; no execution.",state:"operational",route:"/malware-lab",permission:"manual"},
 {id:"binary-headers",name:"Binary Header Analysis",category:"Analysis",description:"PE, ELF and Mach-O header inspection; no execution or disassembly.",state:"partial",route:"/reverse-engineering",permission:"manual"},
 {id:"evidence-vault",name:"Evidence Vault",category:"Governance",description:"Passphrase-encrypted browser-local evidence storage.",state:"operational",route:"/evidence-vault",permission:"manual"},
 {id:"mcp-gateway",name:"MCP Gateway",category:"Orchestration",description:"Authenticated JSON-RPC tools/list and read-only tools/call endpoint.",state:"requires-setup",route:"/settings",permission:"passive",dependency:"CYBERLAB_MCP_API_KEY"},
 {id:"soc-telemetry",name:"SOC Host Telemetry",category:"Operations",description:"On-demand read-only Kali host health snapshot: uptime, load, memory, disk, process count and Nmap availability.",state:"configured",route:"/kali-connection",permission:"local-approved",dependency:"Paired local Kali companion"},
 {id:"cloud-security",name:"Cloud & Container Security",category:"Analysis",description:"Trivy and cloud posture integrations.",state:"planned",route:"/settings",permission:"local-approved"},
 {id:"repository-security",name:"Repository Security",category:"Analysis",description:"Secret scanning, SAST, dependency and IaC checks.",state:"planned",route:"/settings",permission:"manual"},
 {id:"workflow-engine",name:"Workflow Engine",category:"Operations",description:"Audited multi-step workflows, scheduling and notifications.",state:"planned",route:"/settings",permission:"local-approved"},
];

export async function GET() {
 const tools = registry.map(item => {
  let state:State = item.state;
  if (item.id==="ai-agent" && !process.env.OPENROUTER_API_KEY) state="requires-setup";
  if (item.id==="mcp-gateway" && !process.env.CYBERLAB_MCP_API_KEY) state="requires-setup";
  return { ...item, state, dependency: state==="requires-setup" ? item.dependency : undefined };
 });
 return NextResponse.json({ service:"CyberLab AI Tool Registry", generatedAt:new Date().toISOString(), states:{operational:"Verified implemented capability",configured:"Implemented; external/local configuration required",partial:"Implemented with limited coverage", "requires-setup":"Requires configuration or pairing",planned:"Not implemented yet"}, tools }, {headers:{"Cache-Control":"no-store"}});
}
