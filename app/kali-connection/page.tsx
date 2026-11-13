"use client";

import { useState } from "react";
import Link from "next/link";
import { ArrowLeft, Terminal, ShieldCheck, Github, Globe, Search, FileSearch, Network, Link2, Unplug, Radar, LoaderCircle, AlertTriangle, CheckCircle2, Copy } from "lucide-react";

const modules = [
  { icon: Globe, title: "Domain OSINT", detail: "RDAP registration, certificate-transparency names and DNS records." },
  { icon: Search, title: "IP intelligence", detail: "Public IP network registration context through RDAP." },
  { icon: FileSearch, title: "CVE research", detail: "Search NIST's public vulnerability database by vendor, product or CVE." },
  { icon: Terminal, title: "File triage", detail: "SHA-256, file signature, entropy and selected printable-string indicators." },
  { icon: Network, title: "Network evidence", detail: "Parse existing Nmap XML reports into hosts, ports and services." },
];

type Result = { target:string; ports_checked:number[]; duration_seconds:number; method:string; state_summary:{open:number;closed:number;filtered:number}; open_ports:{address:string;port:number;protocol:string;state:string;service:string;product:string;version:string}[]; hosts:{status:string;addresses:{address:string;type:string}[];ports:{port:number;state:string;service:string;product:string;version:string}[]}[]; note:string };

export default function KaliConnectionPage() {
  const [token,setToken]=useState("");
  const [connected,setConnected]=useState(false);
  const [checking,setChecking]=useState(false);
  const [target,setTarget]=useState("");
  const [confirmationTarget,setConfirmationTarget]=useState("");
  const [reference,setReference]=useState("");
  const [confirmed,setConfirmed]=useState(false);
  const [portSpec,setPortSpec]=useState("1-100");
  const [running,setRunning]=useState(false);
  const [error,setError]=useState("");
  const [result,setResult]=useState<Result|null>(null);
  const [copied,setCopied]=useState(false);

  async function connectBridge(){
    setChecking(true);setError("");setConnected(false);
    try{
      const response=await fetch("http://127.0.0.1:8765/health",{headers:{Authorization:"Bearer "+token.trim()},cache:"no-store"});
      const data=await response.json();
      if(!response.ok)throw new Error(data.error||"Could not pair with the local bridge.");
      if(!data.nmap)throw new Error("Bridge is running, but Nmap is missing. Run: sudo apt install -y nmap");
      sessionStorage.setItem("cyberlab.kaliBridgeToken", token.trim());
      setConnected(true);
    }catch(e){setError(e instanceof Error?e.message:"Could not connect. Start the Kali bridge and try again.");}
    finally{setChecking(false);}
  }

  async function runAssessment(event:React.FormEvent){
    event.preventDefault();setRunning(true);setError("");setResult(null);
    try{
      const parsedPorts=new Set<number>();
      for(const item of portSpec.split(",")){
        const part=item.trim();
        if(/^\d+-\d+$/.test(part)){const [start,end]=part.split("-").map(Number);if(start<1||end>65535||start>end||end-start+1>100)throw new Error("Each port range must contain at most 100 valid ports.");for(let p=start;p<=end;p++)parsedPorts.add(p);}
        else if(/^\d+$/.test(part)){const p=Number(part);if(p<1||p>65535)throw new Error("Ports must be between 1 and 65535.");parsedPorts.add(p);}
        else throw new Error("Use a port list such as 22,80,443 or a range such as 1-100.");
        if(parsedPorts.size>100)throw new Error("Choose no more than 100 unique TCP ports.");
      }
      if(!parsedPorts.size)throw new Error("Enter at least one TCP port.");
      const response=await fetch("http://127.0.0.1:8765/scan",{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+token.trim()},body:JSON.stringify({target,confirmationTarget,authorizationReference:reference,authorizationConfirmed:confirmed,ports:[...parsedPorts]})});
      const data=await response.json();
      if(!response.ok)throw new Error(data.error||"Local assessment failed.");
      setResult(data);
    }catch(e){setError(e instanceof Error?e.message:"Local assessment failed. Check that the Kali bridge is running.");}
    finally{setRunning(false);}
  }

  async function copyCommand(){
    await navigator.clipboard.writeText("python3 kali-companion/bridge.py");
    setCopied(true);setTimeout(()=>setCopied(false),1800);
  }

  return <main className="agent-shell">
    <header className="agent-topbar">
      <Link href="/" className="agent-back"><ArrowLeft size={14}/> Main dashboard</Link>
      <div className="agent-brand"><Terminal size={16}/> CYBERLAB AI <span className="agent-top-sep">/</span> KALI COMPANION</div>
      <span className="agent-secure-label"><span/> LOCAL BRIDGE</span>
    </header>
    <section className="agent-main">
      <div className="agent-heading">
        <div className="agent-overline">LOCAL INTEGRATION / KALI LINUX</div>
        <h1>Connect your Kali machine</h1>
        <p>Pair this website with the CyberLab companion running on your Kali computer. The connection stays on your machine at 127.0.0.1; no inbound internet port or public tunnel is needed.</p>
      </div>

      <section className="kali-panel">
        <h2>1. Install or update the companion</h2>
        <pre>git clone https://github.com/abelmiracle377-stack/cyberlab-ai.git{"\n"}cd cyberlab-ai{"\n"}sudo apt update && sudo apt install -y nmap python3{"\n"}python3 kali-companion/cyberlab.py doctor</pre>
        <p>If you already cloned the repository, update it with <code>git pull origin main</code> from inside the repository folder.</p>
        <a href="https://github.com/abelmiracle377-stack/cyberlab-ai/tree/main/kali-companion" target="_blank" rel="noreferrer"><Github size={13}/> View companion source</a>
      </section>

      <section className="kali-panel">
        <h2>2. Start the local bridge on Kali</h2>
        <pre>python3 kali-companion/bridge.py</pre>
        <button className="report-download" type="button" onClick={copyCommand}><Copy size={13}/>{copied?"Copied":"Copy bridge command"}</button>
        <p>The terminal prints a one-time pairing token. Keep it private. The bridge listens only on 127.0.0.1:8765. Keep this terminal open while using the website; press Ctrl+C here to stop it.</p>
      </section>

      <section className="kali-panel">
        <h2>3. Pair this browser with Kali</h2>
        <label className="bridge-label">Pairing token from the Kali terminal<input type="password" autoComplete="off" value={token} onChange={e=>{setToken(e.target.value);setConnected(false);sessionStorage.removeItem("cyberlab.kaliBridgeToken");}} placeholder="Paste the local pairing token"/></label>
        <button className="report-download" type="button" disabled={!token.trim()||checking} onClick={connectBridge}>{checking?<><LoaderCircle size={14}/> Connecting…</>:<><Link2 size={14}/> Connect to Kali</>}</button>
        {connected&&<p className="bridge-connected"><CheckCircle2 size={14}/> Connected to your local Kali bridge. The pairing token is held only in this page's memory.</p>}
      </section>

      {connected&&<section className="kali-panel">
        <h2>4. Run an authorised Nmap assessment</h2>
        <div className="scope-warning"><AlertTriangle size={14}/> Only scan systems you own or have explicit written permission to assess. This checks selected TCP ports and reports open, closed or filtered states where determinable, with light service-version detection. No NSE scripts, exploit attempts, credentials, stealth or denial-of-service options.</div>
        <form className="report-editor" onSubmit={runAssessment}>
          <label>Target IP or hostname<input value={target} onChange={e=>setTarget(e.target.value)} placeholder="192.0.2.10 or lab.example.com" required maxLength={253}/></label>
          <label>Retype exact target to confirm scope<input value={confirmationTarget} onChange={e=>setConfirmationTarget(e.target.value)} placeholder="Type the same target again" required maxLength={253}/></label>
          <label>Authorisation / ticket reference<input value={reference} onChange={e=>setReference(e.target.value)} placeholder="Your approval or engagement reference" required maxLength={160}/></label>
          <label>TCP ports to check<input value={portSpec} onChange={e=>setPortSpec(e.target.value)} placeholder="1-100 or 22,80,443,8080" required/><small>Enter a comma-separated list or range. Maximum 100 ports per run; valid range is 1–65535. Default checks ports 1–100.</small></label>
          <div className="scope-checks"><label><input type="checkbox" checked={confirmed} onChange={e=>setConfirmed(e.target.checked)}/> I own this target or have explicit written authorisation for this exact assessment and confirm it is in scope.</label></div>
          <button className="report-download" type="submit" disabled={running||!confirmed||!reference.trim()||target.trim().toLowerCase()!==confirmationTarget.trim().toLowerCase()}>{running?<><LoaderCircle size={14}/> Running on Kali…</>:<><Radar size={14}/> Run Nmap assessment locally</>}</button>
        </form>
      </section>}

      {error&&<div className="agent-error"><AlertTriangle size={14}/>{error}</div>}
      {result&&<section className="network-results">
        <h2>Local Nmap results</h2>
        <p><strong>{result.target}</strong> · {result.duration_seconds}s · {result.method}</p>
        <div className="bridge-connected"><CheckCircle2 size={14}/> Open: {result.state_summary.open} · Closed: {result.state_summary.closed} · Filtered: {result.state_summary.filtered}</div>
        <div className="network-table-wrap"><table className="network-table"><thead><tr><th>Host</th><th>Port</th><th>Service</th><th>State</th><th>Product / version</th></tr></thead><tbody>{result.hosts.flatMap((host,i)=>host.ports.map(p=><tr key={i+"-"+p.port}><td>{host.addresses[0]?.address||result.target}</td><td>{p.port}</td><td>{p.service}</td><td>{p.state}</td><td>{[p.product,p.version].filter(Boolean).join(" ")||"—"}</td></tr>))}</tbody></table></div>
        <p>{result.note}</p>
      </section>}

      <section className="kali-panel">
        <h2>Other local companion modules</h2>
        <div className="kali-module-grid">{modules.map(({icon:Icon,title,detail})=><div className="kali-module" key={title}><Icon size={17}/><div><strong>{title}</strong><p>{detail}</p></div></div>)}</div>
      </section>

      <div className="kali-warning"><ShieldCheck size={14}/> Privacy: the bridge binds exclusively to 127.0.0.1 and accepts requests only from the official CyberLab site with the local pairing token. No public inbound port is opened. The pairing token is not saved by the website. Scan results are returned to this browser session.</div>
      <div className="agent-disclaimer"><Unplug size={12}/> To disconnect, close this page or clear the token and press Ctrl+C in the Kali terminal. The main dashboard remains available via the top-left link.</div>
    </section>
  </main>;
}
