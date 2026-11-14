"use client";

import { useState } from "react";
import Link from "next/link";
import { ArrowLeft, Activity, Terminal, ShieldCheck, Github, Globe, Search, FileSearch, Network, Link2, Unplug, Radar, LoaderCircle, AlertTriangle, CheckCircle2, Copy } from "lucide-react";
import InvestigationLink from "@/components/investigation-link";

const modules = [
  { icon: Globe, title: "Domain OSINT", detail: "RDAP registration, certificate-transparency names and DNS records." },
  { icon: Search, title: "IP intelligence", detail: "Public IP network registration context through RDAP." },
  { icon: FileSearch, title: "CVE research", detail: "Search NIST's public vulnerability database by vendor, product or CVE." },
  { icon: Terminal, title: "File triage", detail: "SHA-256, file signature, entropy and selected printable-string indicators." },
  { icon: Network, title: "Network evidence", detail: "Parse existing Nmap XML reports into hosts, ports and services." },
];

type Snapshot = { platform:string; release:string; architecture:string; uptime_seconds:number|null; load_average_1_5_15:number[]|null; memory_bytes:Record<string,number>; disk_root_bytes:{total:number;used:number;free:number}; process_count:number|null; nmap_available:boolean; collected_at:string; scope:string };

type KaliTool = {name:string;category:string;binary:string;package:string|null;mode:string;purpose:string;installed:boolean;path:string|null;install_hint:string|null};
type ToolInventory = {categories:{name:string;tools:KaliTool[]}[];tool_count:number;installed_count:number;missing_count:number;note:string};
type TaskPlan = {status:string;summary:string;categories:string[];passive_research_suggestion:{action:string;value:string}|null;service_enumeration_suggestion:{ports:number[];target:string}|null;target:string|null;target_status:string;requires_authorisation:boolean;missing_information:string[];suggested_tools:{name:string;installed:boolean;mode:string;purpose:string;install_hint:string|null}[];safety_notes:string[];steps:string[];execution_started:boolean;note:string};
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
  const [snapshot,setSnapshot]=useState<Snapshot|null>(null);
  const [telemetryBusy,setTelemetryBusy]=useState(false);
  const [toolInventory,setToolInventory]=useState<ToolInventory|null>(null);
  const [toolsBusy,setToolsBusy]=useState(false);
  const [taskPrompt,setTaskPrompt]=useState("");
  const [taskPlan,setTaskPlan]=useState<TaskPlan|null>(null);
  const [planning,setPlanning]=useState(false);
  const [researchAction,setResearchAction]=useState("domain");
  const [researchValue,setResearchValue]=useState("");
  const [researchBusy,setResearchBusy]=useState(false);
  const [researchResult,setResearchResult]=useState<Record<string,unknown>|null>(null);
  const [servicePorts,setServicePorts]=useState("21,22,25,80,443");
  const [serviceBusy,setServiceBusy]=useState(false);
  const [serviceResult,setServiceResult]=useState<Record<string,unknown>|null>(null);
  const [evidenceBusy,setEvidenceBusy]=useState(false);
  const [evidenceReport,setEvidenceReport]=useState<Record<string,unknown>|null>(null);
  const [artifactEvidence,setArtifactEvidence]=useState("");
  const [artifactBusy,setArtifactBusy]=useState(false);
  const [artifactReport,setArtifactReport]=useState<Record<string,unknown>|null>(null);
  const [caseBusy,setCaseBusy]=useState(false);
  const [caseReport,setCaseReport]=useState<Record<string,unknown>|null>(null);

  async function connectBridge(){
    setChecking(true);setError("");setConnected(false);
    try{
      const response=await fetch("http://127.0.0.1:8765/health",{headers:{Authorization:"Bearer "+token.trim()},cache:"no-store"});
      const data=await response.json();
      if(!response.ok)throw new Error(data.error||"Could not pair with the local bridge.");
      const inventoryResponse=await fetch("http://127.0.0.1:8765/tools",{headers:{Authorization:"Bearer "+token.trim()},cache:"no-store"});
      const inventory=await inventoryResponse.json();
      if(!inventoryResponse.ok)throw new Error(inventory.error||"Connected, but the Kali tool inventory could not be loaded. Update the local companion.");
      setToolInventory(inventory as ToolInventory);
      sessionStorage.setItem("cyberlab.kaliBridgeToken", token.trim());
      setConnected(true);
    }catch(e){setError(e instanceof Error?e.message:"Could not connect. Start the Kali bridge and try again.");}
    finally{setChecking(false);}
  }

  async function createTaskPlan(event:React.FormEvent){
    event.preventDefault();setPlanning(true);setError("");setTaskPlan(null);
    try{const response=await fetch("http://127.0.0.1:8765/plan",{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+token.trim()},body:JSON.stringify({prompt:taskPrompt})});const data=await response.json();if(!response.ok)throw new Error(data.error||"Could not plan this task.");setTaskPlan(data as TaskPlan);}
    catch(e){setError(e instanceof Error?e.message:"Task planning failed.");}
    finally{setPlanning(false);}
  }

  async function runPassiveResearch(event:React.FormEvent){
    event.preventDefault();setResearchBusy(true);setError("");setResearchResult(null);
    try{const response=await fetch("http://127.0.0.1:8765/research",{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+token.trim()},body:JSON.stringify({action:researchAction,value:researchValue,limit:10})});const data=await response.json();if(!response.ok)throw new Error(data.error||"Passive research failed.");setResearchResult(data as Record<string,unknown>);}
    catch(e){setError(e instanceof Error?e.message:"Passive research failed.");}
    finally{setResearchBusy(false);}
  }

  async function runServiceEnumeration(event:React.FormEvent){
    event.preventDefault();setServiceBusy(true);setError("");setServiceResult(null);
    try{const ports=servicePorts.split(",").map(value=>Number(value.trim()));if(!ports.length||ports.some(port=>!Number.isInteger(port)))throw new Error("Enter comma-separated supported service ports.");const response=await fetch("http://127.0.0.1:8765/services",{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+token.trim()},body:JSON.stringify({target,confirmationTarget,authorizationReference:reference,authorizationConfirmed:confirmed,ports})});const data=await response.json();if(!response.ok)throw new Error(data.error||"Service identification failed.");setServiceResult(data as Record<string,unknown>);}
    catch(e){setError(e instanceof Error?e.message:"Service identification failed.");}
    finally{setServiceBusy(false);}
  }

  async function createInvestigationCase(){
    setCaseBusy(true);setError("");setCaseReport(null);
    try{
      const serviceReport=evidenceReport;
      const artifactEvidenceReport=artifactReport;
      if(!serviceReport&&!artifactEvidenceReport)throw new Error("Analyse network or artifact evidence before creating a case.");
      const response=await fetch("http://127.0.0.1:8765/evidence/case",{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+token.trim()},body:JSON.stringify({serviceReport,artifactReport:artifactEvidenceReport})});
      const data=await response.json();
      if(!response.ok)throw new Error(data.error||"Could not create the investigation case.");
      setCaseReport(data as Record<string,unknown>);
    }catch(e){setError(e instanceof Error?e.message:"Could not create the investigation case.");}
    finally{setCaseBusy(false);}
  }

  async function exportInvestigationCase(){
    if(!caseReport)return;
    setCaseBusy(true);setError("");
    try{
      const response=await fetch("http://127.0.0.1:8765/evidence/case/export",{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+token.trim()},body:JSON.stringify({caseReport})});
      const data=await response.json();
      if(!response.ok)throw new Error(data.error||"Could not export the investigation case.");
      const caseId=String((caseReport.case as Record<string,unknown>)?.case_id||"cyberlab-case");
      const download=(content:string,type:string,name:string)=>{const blob=new Blob([content],{type});const url=URL.createObjectURL(blob);const anchor=document.createElement("a");anchor.href=url;anchor.download=name;document.body.appendChild(anchor);anchor.click();anchor.remove();URL.revokeObjectURL(url);};
      download(String(data.json_export||""),"application/json;charset=utf-8",caseId+".json");
      download(String(data.html_export||""),"text/html;charset=utf-8",caseId+".html");
      setCaseReport({...caseReport,export_archive:data.archive,export_note:data.note});
    }catch(e){setError(e instanceof Error?e.message:"Could not export the investigation case.");}
    finally{setCaseBusy(false);}
  }

  async function analyseArtifactEvidence(){
    setArtifactBusy(true);setError("");setArtifactReport(null);
    try{
      const parsed=JSON.parse(artifactEvidence);
      if(!parsed||typeof parsed!=="object"||Array.isArray(parsed))throw new Error("Paste a JSON object containing triageResult or recoveryManifest.");
      const response=await fetch("http://127.0.0.1:8765/evidence/artifacts",{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+token.trim()},body:JSON.stringify(parsed)});
      const data=await response.json();
      if(!response.ok)throw new Error(data.error||"Artifact evidence analysis failed.");
      setArtifactReport(data as Record<string,unknown>);
    }catch(e){setError(e instanceof Error?e.message:"Artifact evidence analysis failed. Check the JSON.");}
    finally{setArtifactBusy(false);}
  }

  async function analyseServiceEvidence(){
    if(!serviceResult)return;
    setEvidenceBusy(true);setError("");setEvidenceReport(null);
    try{
      const response=await fetch("http://127.0.0.1:8765/evidence/report",{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+token.trim()},body:JSON.stringify({serviceResult})});
      const data=await response.json();
      if(!response.ok)throw new Error(data.error||"Evidence analysis failed.");
      setEvidenceReport(data as Record<string,unknown>);
    }catch(e){setError(e instanceof Error?e.message:"Evidence analysis failed.");}
    finally{setEvidenceBusy(false);}
  }

  async function refreshToolInventory(){
    setToolsBusy(true);setError("");
    try{const response=await fetch("http://127.0.0.1:8765/tools",{headers:{Authorization:"Bearer "+token.trim()},cache:"no-store"});const data=await response.json();if(!response.ok)throw new Error(data.error||"Could not refresh the Kali tool inventory.");setToolInventory(data as ToolInventory);}
    catch(e){setError(e instanceof Error?e.message:"Tool inventory request failed.");}
    finally{setToolsBusy(false);}
  }

  async function refreshTelemetry(){
    setTelemetryBusy(true);setError("");
    try{
      const response=await fetch("http://127.0.0.1:8765/system",{headers:{Authorization:"Bearer "+token.trim()},cache:"no-store"});
      const data=await response.json();
      if(!response.ok)throw new Error(data.error||"Could not retrieve local host telemetry.");
      setSnapshot(data.metrics as Snapshot);
    }catch(e){setError(e instanceof Error?e.message:"Local telemetry request failed.");}
    finally{setTelemetryBusy(false);}
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
        <pre>git clone https://github.com/abelmiracle377-stack/cyberlab-ai.git{"\n"}cd cyberlab-ai{"\n"}git checkout feature/additive-forensics-recovery{"\n"}sudo apt update && sudo apt install -y nmap python3 gddrescue testdisk foremost ntfs-3g{"\n"}python3 kali-companion/cyberlab.py doctor</pre>
        <p>For this preview build, check out <code>feature/additive-forensics-recovery</code> before starting the bridge. After the pull request is merged and the production app is updated, switch back to <code>main</code> and pull the latest changes.</p>
        <a href="https://github.com/abelmiracle377-stack/cyberlab-ai/tree/main/kali-companion" target="_blank" rel="noreferrer"><Github size={13}/> View companion source</a>
      </section>

      <section className="kali-panel">
        <h2>2. Start the local bridge on Kali</h2>
        <pre>sudo python3 kali-companion/bridge.py</pre>
        <button className="report-download" type="button" onClick={copyCommand}><Copy size={13}/>{copied?"Copied":"Copy bridge command"}</button>
        <p>The terminal prints a one-time pairing token. Keep it private. The bridge listens only on 127.0.0.1:8765. Running with sudo enables explicitly approved disk imaging; it gives the local bridge elevated privileges, so keep the token private and stop the bridge when finished. Keep this terminal open while using the website; press Ctrl+C here to stop it.</p>
      </section>

      <section className="kali-panel">
        <h2>3. Pair this browser with Kali</h2>
        <label className="bridge-label">Pairing token from the Kali terminal<input type="password" autoComplete="off" value={token} onChange={e=>{setToken(e.target.value);setConnected(false);sessionStorage.removeItem("cyberlab.kaliBridgeToken");}} placeholder="Paste the local pairing token"/></label>
        <button className="report-download" type="button" disabled={!token.trim()||checking} onClick={connectBridge}>{checking?<><LoaderCircle size={14}/> Connecting…</>:<><Link2 size={14}/> Connect to Kali</>}</button>
        {connected&&<p className="bridge-connected"><CheckCircle2 size={14}/> Connected to your local Kali bridge. The pairing token is held only in this page's memory.</p>}
      </section>

      {connected&&toolInventory&&<section className="kali-panel">
        <h2>4. Kali tool inventory</h2>
        <p>{toolInventory.installed_count} of {toolInventory.tool_count} catalogued tools detected · {toolInventory.missing_count} missing. Inventory checks executable availability only; it does not install or launch tools.</p>
        <button className="report-download" type="button" onClick={refreshToolInventory} disabled={toolsBusy}>{toolsBusy?<><LoaderCircle size={14}/> Checking tools…</>:<><Activity size={14}/> Refresh tool inventory</>}</button>
        <div className="kali-module-grid" style={{marginTop:14}}>
          {toolInventory.categories.map(category=><div className="kali-module" key={category.name} style={{display:"block"}}>
            <strong>{category.name}</strong>
            <div style={{marginTop:8,display:"grid",gap:8}}>
              {category.tools.map(tool=><div key={tool.name} style={{borderTop:"1px solid var(--line)",paddingTop:7}}>
                <div style={{display:"flex",justifyContent:"space-between",gap:8,alignItems:"center"}}><strong>{tool.name}</strong><span>{tool.installed?"INSTALLED":"MISSING"}</span></div>
                <p>{tool.purpose}</p><small>Mode: {tool.mode.replaceAll("_"," ")}</small>
                {!tool.installed&&tool.install_hint&&<p><code>{tool.install_hint}</code></p>}
              </div>)}
            </div>
          </div>)}
        </div>
        <p className="network-note">{toolInventory.note} Review package suggestions and install them yourself in the Kali terminal.</p>
      </section>}

      {connected&&<section className="kali-panel">
        <h2>5. Describe any authorised cybersecurity task</h2>
        <p>Ask a question in plain language: network or service enumeration, web security, DNS/OSINT, vulnerability research, FTP/SMB/SSH analysis, Metasploit module research, offline password-hash auditing, wireless lab assessment, packet analysis, Active Directory, digital forensics, malware triage or reverse engineering. You do not need to write Kali commands.</p>
        <form className="report-editor" onSubmit={createTaskPlan}>
          <label>Task, question, scan objective or lab prompt<textarea value={taskPrompt} onChange={e=>{setTaskPrompt(e.target.value);setTaskPlan(null);}} placeholder="Example: I have written permission to assess lab.example.org. Identify exposed services and explain what evidence to collect next. Or paste a TryHackMe / HTB question." required maxLength={4000} rows={5}/></label>
          <small>Up to 4,000 characters. A target mentioned in the text is only a candidate; it is not treated as proof of permission.</small>
          <button className="report-download" type="submit" disabled={planning||!taskPrompt.trim()}>{planning?<><LoaderCircle size={14}/> Planning task…</>:<><Activity size={14}/> Analyse task and build plan</>}</button>
        </form>
        {taskPlan&&<div className="network-results">
          <h3>{taskPlan.summary}</h3>
          <p><strong>Target:</strong> {taskPlan.target||"Not supplied"} · {taskPlan.target_status}</p>
          {taskPlan.passive_research_suggestion&&<button className="report-download" type="button" onClick={()=>{setResearchAction(taskPlan.passive_research_suggestion!.action);setResearchValue(taskPlan.passive_research_suggestion!.value);setResearchResult(null);}}>Prepare passive domain research for {taskPlan.passive_research_suggestion.value}</button>}
          <p><strong>Execution:</strong> {taskPlan.execution_started?"Started":"Not started — planning only"}</p>
          {taskPlan.target&&taskPlan.requires_authorisation&&<button className="report-download" type="button" onClick={()=>{setTarget(taskPlan.target||"");setConfirmationTarget("");setConfirmed(false);setResult(null);}}>Use candidate target in authorised Nmap form</button>}
          {taskPlan.service_enumeration_suggestion&&<button className="report-download" type="button" onClick={()=>{setTarget(taskPlan.service_enumeration_suggestion!.target);setConfirmationTarget("");setConfirmed(false);setServicePorts(taskPlan.service_enumeration_suggestion!.ports.join(","));setServiceResult(null);}}>Prepare service identification for {taskPlan.service_enumeration_suggestion.target}</button>}
          {taskPlan.missing_information.length>0&&<><strong>Information still needed</strong><ul>{taskPlan.missing_information.map((item,i)=><li key={i}>{item}</li>)}</ul></>}
          {taskPlan.safety_notes.length>0&&<><strong>Safety boundaries</strong><ul>{taskPlan.safety_notes.map((item,i)=><li key={i}>{item}</li>)}</ul></>}
          <strong>Suggested local tools</strong>
          <div className="network-table-wrap"><table className="network-table"><thead><tr><th>Tool</th><th>Availability</th><th>Mode</th><th>Purpose / install guidance</th></tr></thead><tbody>{taskPlan.suggested_tools.map(tool=><tr key={tool.name}><td>{tool.name}</td><td>{tool.installed?"Installed":"Missing"}</td><td>{tool.mode.replaceAll("_"," ")}</td><td>{tool.purpose}{!tool.installed&&tool.install_hint?<><br/><code>{tool.install_hint}</code></>:null}</td></tr>)}</tbody></table></div>
          <strong>Proposed workflow</strong><ol>{taskPlan.steps.map((step,i)=><li key={i}>{step}</li>)}</ol>
          <p className="network-note">{taskPlan.note}</p>
        </div>}
      </section>}

      {connected&&<section className="kali-panel">
        <h2>7. SOC host telemetry</h2>
        <p>Read-only health snapshot from the paired Kali machine. It does not collect usernames, process names, command lines, files or network payloads.</p>
        <button className="report-download" type="button" onClick={refreshTelemetry} disabled={telemetryBusy}>{telemetryBusy?<><LoaderCircle size={14}/> Reading local metrics…</>:<><Activity size={14}/> Refresh host telemetry</>}</button>
        {snapshot&&<div className="network-results">
          <p><strong>{snapshot.platform} {snapshot.release}</strong> · {snapshot.architecture} · captured {new Date(snapshot.collected_at).toLocaleTimeString()}</p>
          <div className="kali-module-grid">
            <div className="kali-module"><Activity size={16}/><div><strong>Uptime</strong><p>{snapshot.uptime_seconds===null?"Unavailable":Math.floor(snapshot.uptime_seconds/3600)+"h "+Math.floor((snapshot.uptime_seconds%3600)/60)+"m"}</p></div></div>
            <div className="kali-module"><Activity size={16}/><div><strong>Load average</strong><p>{snapshot.load_average_1_5_15?.map(v=>v.toFixed(2)).join(" / ")||"Unavailable"}</p></div></div>
            <div className="kali-module"><Activity size={16}/><div><strong>Memory available</strong><p>{snapshot.memory_bytes.MemAvailable===undefined?"Unavailable":(snapshot.memory_bytes.MemAvailable/1073741824).toFixed(2)+" GB"}</p></div></div>
            <div className="kali-module"><Activity size={16}/><div><strong>Root disk free</strong><p>{(snapshot.disk_root_bytes.free/1073741824).toFixed(2)+" GB / "+(snapshot.disk_root_bytes.total/1073741824).toFixed(2)+" GB"}</p></div></div>
            <div className="kali-module"><Activity size={16}/><div><strong>Process count</strong><p>{snapshot.process_count??"Unavailable"}</p></div></div>
            <div className="kali-module"><Activity size={16}/><div><strong>Nmap</strong><p>{snapshot.nmap_available?"Installed":"Not found"}</p></div></div>
          </div>
          <p className="network-note">{snapshot.scope}</p>
          <InvestigationLink source="kali-soc-telemetry" eventType="host-snapshot" title={`Kali host snapshot: ${snapshot.platform} ${snapshot.release}`} severity="informational" details={{ ...snapshot }} />
        </div>}
      </section>}

      {connected&&<section className="kali-panel">
        <h2>8. Safe service identification</h2>
        <p>Identify common exposed services using bounded TCP connections and minimal protocol metadata. HTTP uses HEAD, TLS reads certificate metadata, and FTP/SSH/SMTP/POP3/IMAP read available banners. No login, credential attempts, file transfer or exploit payloads.</p>
        <form className="report-editor" onSubmit={runServiceEnumeration}>
          <label>Target IP or hostname<input value={target} onChange={e=>{setTarget(e.target.value);setServiceResult(null);}} placeholder="192.0.2.10 or lab.example.com" required maxLength={253}/></label>
          <label>Retype exact target to confirm scope<input value={confirmationTarget} onChange={e=>setConfirmationTarget(e.target.value)} placeholder="Type the same target again" required maxLength={253}/></label>
          <label>Authorisation / ticket reference<input value={reference} onChange={e=>setReference(e.target.value)} placeholder="Your approval or engagement reference" required maxLength={160}/></label>
          <label>Service ports<input value={servicePorts} onChange={e=>setServicePorts(e.target.value)} placeholder="21,22,25,80,443" required/><small>Choose up to 8 reviewed ports: 21, 22, 25, 80, 110, 143, 443, 445, 587, 993, 995, 8080, 8443.</small></label>
          <div className="scope-checks"><label><input type="checkbox" checked={confirmed} onChange={e=>setConfirmed(e.target.checked)}/> I own this target or have explicit written authorisation for this exact assessment and confirm it is in scope.</label></div>
          <button className="report-download" type="submit" disabled={serviceBusy||!confirmed||!reference.trim()||target.trim().toLowerCase()!==confirmationTarget.trim().toLowerCase()}>{serviceBusy?<><LoaderCircle size={14}/> Identifying services…</>:<><Network size={14}/> Identify services locally</>}</button>
        </form>
        {serviceResult&&<div className="network-results"><h3>Service identification evidence</h3><pre style={{whiteSpace:"pre-wrap",overflowWrap:"anywhere",maxHeight:520,overflow:"auto"}}>{JSON.stringify(serviceResult,null,2)}</pre><button className="report-download" type="button" onClick={analyseServiceEvidence} disabled={evidenceBusy}>{evidenceBusy?<><LoaderCircle size={14}/> Analysing evidence…</>:<><FileSearch size={14}/> Correlate evidence with NIST CVEs</>}</button>{evidenceReport&&<><h3>Evidence-led analysis</h3><p>{String(evidenceReport.note||"")}</p><pre style={{whiteSpace:"pre-wrap",overflowWrap:"anywhere",maxHeight:520,overflow:"auto"}}>{JSON.stringify(evidenceReport,null,2)}</pre></>}</div>}
      </section>}

      {connected&&<section className="kali-panel">
        <h2>9. Static artifact and recovery evidence</h2>
        <p>Paste JSON from <code>python3 kali-companion/cyberlab.py triage /path/to/sample</code> as a <code>triageResult</code>, or paste a <code>cyberlab-recovery-manifest.json</code> as a <code>recoveryManifest</code>. This analysis is offline and non-executing; it does not upload samples or declare files malicious.</p>
        <label className="bridge-label">Triage result or recovery manifest JSON<textarea value={artifactEvidence} onChange={e=>{setArtifactEvidence(e.target.value);setArtifactReport(null);}} placeholder='{"triageResult":{"file_name":"sample.bin","size_bytes":1024,"sha256":"...","entropy":6.2,"indicator_groups":[],"matched_strings":[]}}' rows={7}/></label>
        <button className="report-download" type="button" onClick={analyseArtifactEvidence} disabled={artifactBusy||!artifactEvidence.trim()}>{artifactBusy?<><LoaderCircle size={14}/> Analysing artifact evidence…</>:<><FileSearch size={14}/> Analyse static artifact evidence</>}</button>
        {artifactReport&&<div className="network-results"><h3>Artifact evidence report</h3><pre style={{whiteSpace:"pre-wrap",overflowWrap:"anywhere",maxHeight:520,overflow:"auto"}}>{JSON.stringify(artifactReport,null,2)}</pre></div>}
      </section>}

      {connected&&<section className="kali-panel">
        <h2>10. Unified investigation case</h2>
        <p>Combine completed service/CVE analysis and static artifact/recovery analysis into one provenance report. The local audit ledger records evidence digests and case metadata, not raw samples, banners or recovered contents.</p>
        <button className="report-download" type="button" onClick={createInvestigationCase} disabled={caseBusy||(!evidenceReport&&!artifactReport)}>{caseBusy?<><LoaderCircle size={14}/> Creating case…</>:<><FileSearch size={14}/> Create unified case report</>}</button>
        {caseReport&&<div className="network-results"><h3>Investigation case created</h3><button className="report-download" type="button" onClick={exportInvestigationCase} disabled={caseBusy}>{caseBusy?<><LoaderCircle size={14}/> Preparing exports…</>:<><FileSearch size={14}/> Export JSON + HTML and archive locally</>}</button>{caseReport.export_archive&&<p className="network-note">Private archive: {String((caseReport.export_archive as Record<string,unknown>).directory)} · JSON and HTML downloads started. Verify the manifest hashes before relying on exported evidence.</p>}<pre style={{whiteSpace:"pre-wrap",overflowWrap:"anywhere",maxHeight:620,overflow:"auto"}}>{JSON.stringify(caseReport,null,2)}</pre></div>}
      </section>}

      {connected&&<section className="kali-panel">
        <h2>11. Run an authorised Nmap assessment</h2>
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
