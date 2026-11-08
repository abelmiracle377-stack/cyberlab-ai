import Link from "next/link";
import { ArrowLeft, Terminal, ShieldCheck, Github, Globe, Search, FileSearch, Network } from "lucide-react";

const modules = [
  { icon: Globe, title: "Domain OSINT", detail: "RDAP registration, certificate-transparency names and DNS records." },
  { icon: Search, title: "IP intelligence", detail: "Public IP network registration context through RDAP." },
  { icon: FileSearch, title: "CVE research", detail: "Search NIST's public vulnerability database by vendor, product or CVE." },
  { icon: Terminal, title: "File triage", detail: "SHA-256, file signature, entropy and selected printable-string indicators." },
  { icon: Network, title: "Network evidence", detail: "Parse an existing Nmap XML report into hosts, ports and services." },
];

export default function KaliConnectionPage() {
  return <main className="agent-shell">
    <header className="agent-topbar">
      <Link href="/" className="agent-back"><ArrowLeft size={14}/> Dashboard</Link>
      <div className="agent-brand"><Terminal size={16}/> CYBERLAB AI <span className="agent-top-sep">/</span> KALI COMPANION</div>
      <span className="agent-secure-label"><span/> KALI RESEARCH TOOLKIT</span>
    </header>
    <section className="agent-main">
      <div className="agent-heading">
        <div className="agent-overline">LOCAL INTEGRATION / KALI LINUX</div>
        <h1>Kali research companion</h1>
        <p>Run passive OSINT and vulnerability lookups from your Kali terminal, then analyse local files and network evidence. No Python packages or API keys are required.</p>
      </div>
      <div className="kali-status"><ShieldCheck size={16}/><div><strong>Companion source available</strong><span>Public-source lookups require an internet connection. File triage and XML parsing run locally.</span></div></div>
      <section className="kali-panel">
        <h2>What it includes</h2>
        <div className="kali-module-grid">
          {modules.map(({icon: Icon, title, detail}) => <div className="kali-module" key={title}><Icon size={17}/><div><strong>{title}</strong><p>{detail}</p></div></div>)}
        </div>
      </section>
      <section className="kali-panel">
        <h2>1. Install on Kali</h2>
        <p>Open a terminal and run these commands:</p>
        <pre>git clone https://github.com/abelmiracle377-stack/cyberlab-ai.git{"\n"}cd cyberlab-ai{"\n"}python3 kali-companion/cyberlab.py doctor{"\n"}python3 kali-companion/cyberlab.py --help</pre>
        <a href="https://github.com/abelmiracle377-stack/cyberlab-ai/tree/main/kali-companion" target="_blank" rel="noreferrer"><Github size={13}/> View companion source and guide</a>
      </section>
      <section className="kali-panel">
        <h2>2. Passive OSINT examples</h2>
        <p>Use a public domain or public IP you are researching:</p>
        <pre>python3 kali-companion/cyberlab.py domain example.com{"\n"}python3 kali-companion/cyberlab.py dns example.com{"\n"}python3 kali-companion/cyberlab.py ip 8.8.8.8</pre>
        <p>Domain research combines public RDAP data, certificate-transparency results and DNS. IP lookup returns network registration context, not a person's identity or exact location.</p>
      </section>
      <section className="kali-panel">
        <h2>3. Vulnerability intelligence</h2>
        <p>Search NIST's public NVD catalogue:</p>
        <pre>python3 kali-companion/cyberlab.py cve "OpenSSH" --limit 10</pre>
      </section>
      <section className="kali-panel">
        <h2>4. Local file and network evidence</h2>
        <pre>python3 kali-companion/cyberlab.py triage ./sample.bin{"\n"}python3 kali-companion/cyberlab.py nmap-xml ./authorised-scan.xml</pre>
        <p>File triage is static only. Nmap XML is parsed from a report you already have; the companion does not launch scans.</p>
      </section>
      <section className="kali-panel">
        <h2>5. Save results as JSON</h2>
        <pre>python3 kali-companion/cyberlab.py domain example.com --output domain-report.json{"\n"}python3 kali-companion/cyberlab.py cve "OpenSSH" -o cve-report.json</pre>
      </section>
      <div className="kali-warning"><ShieldCheck size={14}/>Scope and safety: the companion makes read-only requests to public data providers. It does not perform active scanning, brute-force enumeration, exploitation, credential attacks, shell execution or malware execution. Use any separate assessment tools only on systems you own or are explicitly authorised to test.</div>
      <div className="agent-disclaimer"><ShieldCheck size={12}/> Python 3.9+ required. The current Kali companion is a research CLI, not yet an AI-driven local agent or a synchronised website client.</div>
    </section>
  </main>;
}
