import Link from "next/link";
import { ArrowLeft, Terminal, ShieldCheck, Github, Download } from "lucide-react";
export default function KaliConnectionPage(){
 return <main className="agent-shell"><header className="agent-topbar"><Link href="/" className="agent-back"><ArrowLeft size={14}/> Dashboard</Link><div className="agent-brand"><Terminal size={16}/> CYBERLAB AI <span className="agent-top-sep">/</span> KALI COMPANION</div><span className="agent-secure-label"><span/> OFFLINE TOOLKIT</span></header>
 <section className="agent-main"><div className="agent-heading"><div className="agent-overline">LOCAL INTEGRATION / 008</div><h1>Kali Linux companion</h1><p>Use the lightweight offline Python companion to inspect files and parse existing Nmap XML reports from Kali.</p></div>
 <div className="kali-status"><ShieldCheck size={16}/><div><strong>Offline companion available</strong><span>No API key, cloud connection or additional Python package is required.</span></div></div>
 <section className="kali-panel"><h2>1. Get the repository</h2><p>Clone the CyberLab AI repository on your Kali machine.</p><pre>git clone https://github.com/abelmiracle377-stack/cyberlab-ai.git{"\n"}cd cyberlab-ai</pre><a href="https://github.com/abelmiracle377-stack/cyberlab-ai/tree/main/kali-companion" target="_blank" rel="noreferrer"><Github size={13}/> View companion source</a></section>
 <section className="kali-panel"><h2>2. Check the available commands</h2><pre>python3 kali-companion/cyberlab.py --help</pre></section>
 <section className="kali-panel"><h2>3. Static file triage</h2><p>Calculate SHA-256, identify common file signatures, estimate entropy and extract selected printable indicators. Samples are not executed.</p><pre>python3 kali-companion/cyberlab.py triage ./sample.bin{"\n"}python3 kali-companion/cyberlab.py triage ./sample.bin &gt; triage-report.json</pre></section>
 <section className="kali-panel"><h2>4. Parse an existing Nmap report</h2><p>Import an XML report from an assessment you are authorised to perform. This command does not run Nmap.</p><pre>python3 kali-companion/cyberlab.py nmap-xml ./scan.xml{"\n"}python3 kali-companion/cyberlab.py nmap-xml ./scan.xml &gt; network-report.json</pre></section>
 <div className="kali-warning"><ShieldCheck size={14}/>This first companion is intentionally offline and restricted. It does not expose a remote shell, run scans, exploit systems, execute malware or connect back to the website. Authenticated website synchronisation can be added later with a dedicated scoped credential flow.</div>
 <div className="agent-disclaimer"><ShieldCheck size={12}/> Python 3.9+ is required. The companion uses only the Python standard library.</div>
 </section></main>;
}
