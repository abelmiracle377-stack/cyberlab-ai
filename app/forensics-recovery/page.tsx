"use client";

import { useEffect, useMemo, useState, type ChangeEvent } from "react";
import Link from "next/link";
import { ArrowLeft, Download, FileSearch, HardDriveDownload, ShieldCheck } from "lucide-react";

type Kind = "JPEG" | "PNG" | "GIF" | "PDF";
type Recovered = { id:string; kind:Kind; start:number; end:number; size:number; name:string };
type BlockDevice = {name:string;path:string;type:string;size:number;ro:boolean;tran?:string;model?:string;fstype?:string;mountpoints?:Array<string|null>};
type AcquisitionJob = {id:string;state:string;source:string;image:string;map:string;output?:string;message:string;return_code?:number};
const MAX_BYTES = 256 * 1024 * 1024;
const signatures = {
  jpegStart: [0xff,0xd8,0xff], jpegEnd: [0xff,0xd9],
  pngStart: [0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a],
  pngEnd: [0x49,0x45,0x4e,0x44,0xae,0x42,0x60,0x82],
  gif87: [0x47,0x49,0x46,0x38,0x37,0x61], gif89: [0x47,0x49,0x46,0x38,0x39,0x61],
  pdf: [0x25,0x50,0x44,0x46,0x2d], pdfEnd: [0x25,0x25,0x45,0x4f,0x46]
};
function findBytes(data:Uint8Array, pattern:number[], from=0):number {
  outer: for(let i=from;i<=data.length-pattern.length;i++){for(let j=0;j<pattern.length;j++)if(data[i+j]!==pattern[j])continue outer;return i;}return -1;
}
function carve(data:Uint8Array):Recovered[]{
  const found:Recovered[]=[];
  const add=(kind:Kind,start:number,end:number)=>{if(end>start&&end<=data.length)found.push({id:`${kind}-${start}-${end}`,kind,start,end,size:end-start,name:`recovered-${String(found.length+1).padStart(3,"0")}.${kind==="JPEG"?"jpg":kind.toLowerCase()}`});};
  let cursor=0;
  while(cursor<data.length){
    const jpg=findBytes(data,signatures.jpegStart,cursor), png=findBytes(data,signatures.pngStart,cursor);
    const gifA=findBytes(data,signatures.gif87,cursor),gifB=findBytes(data,signatures.gif89,cursor);
    const gif=gifA<0?gifB:gifB<0?gifA:Math.min(gifA,gifB);
    const pdf=findBytes(data,signatures.pdf,cursor);
    const candidates=[{kind:"JPEG" as Kind,start:jpg},{kind:"PNG" as Kind,start:png},{kind:"GIF" as Kind,start:gif},{kind:"PDF" as Kind,start:pdf}].filter(x=>x.start>=0).sort((a,b)=>a.start-b.start);
    if(!candidates.length)break;
    const item=candidates[0];let end=-1;
    if(item.kind==="JPEG"){const p=findBytes(data,signatures.jpegEnd,item.start+3);if(p>=0)end=p+2;}
    if(item.kind==="PNG"){const p=findBytes(data,signatures.pngEnd,item.start+8);if(p>=0)end=p+signatures.pngEnd.length;}
    if(item.kind==="GIF"){const p=data.indexOf(0x3b,item.start+6);if(p>=0)end=p+1;}
    if(item.kind==="PDF"){const p=findBytes(data,signatures.pdfEnd,item.start+5);if(p>=0)end=p+signatures.pdfEnd.length;}
    if(end>item.start){add(item.kind,item.start,end);cursor=end;}else cursor=item.start+1;
  }
  return found;
}
function formatBytes(n:number){return n<1024?`${n} B`:n<1024*1024?`${(n/1024).toFixed(1)} KB`:`${(n/1024/1024).toFixed(2)} MB`;}

export default function ForensicsRecoveryPage(){
  const [source,setSource]=useState<File|null>(null),[items,setItems]=useState<Recovered[]>([]),[previewUrls,setPreviewUrls]=useState<Record<string,string>>({}),[busy,setBusy]=useState(false),[message,setMessage]=useState(""),[hash,setHash]=useState("");
  const [bridgeToken,setBridgeToken]=useState(""),[paired,setPaired]=useState(false),[devices,setDevices]=useState<BlockDevice[]>([]),[selectedDevice,setSelectedDevice]=useState(""),[destinationDirectory,setDestinationDirectory]=useState("/mnt/backup"),[imageFilename,setImageFilename]=useState("cyberlab-disk.img"),[confirmationSource,setConfirmationSource]=useState(""),[bridgeBusy,setBridgeBusy]=useState(false),[bridgeMessage,setBridgeMessage]=useState(""),[job,setJob]=useState<AcquisitionJob|null>(null),[recoveryParent,setRecoveryParent]=useState("/mnt/backup"),[confirmImage,setConfirmImage]=useState(""),[recoveryJob,setRecoveryJob]=useState<AcquisitionJob|null>(null);
  useEffect(()=>()=>{Object.values(previewUrls).forEach(url=>URL.revokeObjectURL(url));},[previewUrls]);
  const total=useMemo(()=>items.reduce((sum,x)=>sum+x.size,0),[items]);
  async function pairKali(){
    setBridgeBusy(true);setBridgeMessage("");setPaired(false);
    try{
      const headers={Authorization:"Bearer "+bridgeToken.trim()};
      const health=await fetch("http://127.0.0.1:8765/health",{headers,cache:"no-store"});
      const h=await health.json();if(!health.ok)throw new Error(h.error||"Could not connect to Kali.");
      const inventory=await fetch("http://127.0.0.1:8765/forensics/devices",{headers,cache:"no-store"});
      const d=await inventory.json();if(!inventory.ok)throw new Error(d.error||"Could not read block-device inventory.");
      setDevices((d.devices||[]).flatMap((item:BlockDevice)=>[item,...((item as any).children||[])]).filter((item:BlockDevice)=>item.path&&["disk","part"].includes(item.type)));
      setPaired(true);setBridgeMessage("Kali connected. Device inventory is read-only; no drive has been mounted or modified.");
    }catch(e){setBridgeMessage(e instanceof Error?e.message:"Kali connection failed.");}
    finally{setBridgeBusy(false);}
  }
  async function refreshDevices(){
    const response=await fetch("http://127.0.0.1:8765/forensics/devices",{headers:{Authorization:"Bearer "+bridgeToken.trim()},cache:"no-store"});
    const data=await response.json();if(!response.ok)throw new Error(data.error||"Device inventory failed.");
    setDevices((data.devices||[]).flatMap((item:BlockDevice)=>[item,...((item as any).children||[])]).filter((item:BlockDevice)=>item.path&&["disk","part"].includes(item.type)));
  }
  async function runForemost(){
    if(!job||job.state!=="completed"||confirmImage!==job.image){setBridgeMessage("Confirm the exact completed image path before starting recovery.");return;}
    setBridgeBusy(true);
    try{
      const response=await fetch("http://127.0.0.1:8765/forensics/foremost",{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+bridgeToken.trim()},body:JSON.stringify({imageJobId:job.id,outputDirectory:recoveryParent,confirmationImage:confirmImage})});
      const data=await response.json();if(!response.ok)throw new Error(data.error||"Foremost recovery could not start.");
      setRecoveryJob(data.job);setBridgeMessage(data.note||"Foremost recovery started.");
      const id=data.job.id;
      const poll=async():Promise<void>=>{
        const status=await fetch("http://127.0.0.1:8765/forensics/jobs/"+id,{headers:{Authorization:"Bearer "+bridgeToken.trim()},cache:"no-store"});
        const payload=await status.json();if(!status.ok)throw new Error(payload.error||"Could not read recovery status.");
        setRecoveryJob(payload.job);
        if(payload.job.state==="running"){await new Promise(resolve=>setTimeout(resolve,3000));return poll();}
        setBridgeMessage(payload.job.message||"Recovery job finished.");
      };
      void poll().catch(e=>setBridgeMessage(e instanceof Error?e.message:"Could not monitor recovery job."));
    }catch(e){setBridgeMessage(e instanceof Error?e.message:"Foremost recovery failed.");}
    finally{setBridgeBusy(false);}
  }
  async function acquireImage(){
    if(!selectedDevice||confirmationSource!==selectedDevice){setBridgeMessage("Select a source and retype its exact device path to confirm.");return;}
    setBridgeBusy(true);setBridgeMessage("Submitting protected imaging job…");
    try{
      const response=await fetch("http://127.0.0.1:8765/forensics/image",{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+bridgeToken.trim()},body:JSON.stringify({source:selectedDevice,destinationDirectory,filename:imageFilename,confirmationSource})});
      const data=await response.json();if(!response.ok)throw new Error(data.error||"Disk imaging could not start.");
      setJob(data.job);setBridgeMessage(data.note||"Disk imaging started.");
      const jobId=data.job.id;
      const poll=async():Promise<void>=>{
        const status=await fetch("http://127.0.0.1:8765/forensics/jobs/"+jobId,{headers:{Authorization:"Bearer "+bridgeToken.trim()},cache:"no-store"});
        const payload=await status.json();if(!status.ok)throw new Error(payload.error||"Could not read imaging status.");
        setJob(payload.job);
        if(payload.job.state==="running"){await new Promise(resolve=>setTimeout(resolve,3000));return poll();}
        setBridgeMessage(payload.job.message||"Imaging job finished.");
      };
      void poll().catch(e=>setBridgeMessage(e instanceof Error?e.message:"Could not monitor imaging job."));
    }catch(e){setBridgeMessage(e instanceof Error?e.message:"Disk imaging failed.");}
    finally{setBridgeBusy(false);}
  }
  async function choose(e:ChangeEvent<HTMLInputElement>){setSource(e.target.files?.[0]??null);setItems([]);setPreviewUrls({});setHash("");setMessage("");}
  async function scan(){if(!source)return;if(source.size>MAX_BYTES){setMessage("This browser-based scanner is limited to 256 MB per source image. Use a dedicated forensic workstation for larger images.");return;}
    setBusy(true);setItems([]);setPreviewUrls({});setMessage("Reading source image locally…");
    try{const buffer=await source.arrayBuffer();const data=new Uint8Array(buffer);const digest=await crypto.subtle.digest("SHA-256",buffer);const hex=Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,"0")).join("");const results=carve(data);const previews:Record<string,string>={};for(const item of results){if(item.kind!=="PDF"){const mime=item.kind==="JPEG"?"image/jpeg":item.kind==="PNG"?"image/png":"image/gif";previews[item.id]=URL.createObjectURL(new Blob([data.slice(item.start,item.end)],{type:mime}));}}setPreviewUrls(previews);setHash(hex);setItems(results);setMessage(results.length?`Found ${results.length} signature-bounded candidate(s). Preview and validate each file before relying on it.`:"No supported contiguous file signatures were found.");}
    catch{setMessage("The source could not be read. Try a supported raw image or smaller evidence file.");}
    finally{setBusy(false);}
  }
  async function download(item:Recovered){if(!source)return;const buffer=await source.slice(item.start,item.end).arrayBuffer();const blob=new Blob([buffer],{type:item.kind==="JPEG"?"image/jpeg":item.kind==="PNG"?"image/png":item.kind==="GIF"?"image/gif":"application/pdf"});const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download=item.name;a.click();URL.revokeObjectURL(url);}
  return <main className="agent-shell">
    <header className="agent-topbar"><Link href="/" className="agent-back"><ArrowLeft size={14}/> Dashboard</Link><div className="agent-brand"><HardDriveDownload size={16}/> CYBERLAB AI <span className="agent-top-sep">/</span> DIGITAL FORENSICS</div><span className="agent-secure-label"><span/> LOCAL / READ-ONLY</span></header>
    <section className="agent-main">
      <div className="agent-heading"><div className="agent-overline">ANALYSIS & EVIDENCE / ADDITIVE MODULE</div><h1>File & picture recovery</h1><p>Carve contiguous JPEG, PNG, GIF and PDF candidates from a user-supplied disk image or forensic export. Source data is read locally and never modified or uploaded.</p></div>
      <div className="vault-security"><ShieldCheck size={16}/><div><strong>Non-destructive evidence handling</strong><p>CyberLab reads a copy you select, records its SHA-256 hash and exports recovered candidates as new files. It never writes to the source device.</p></div></div>
      <section className="module-page-panel panel" style={{marginTop:18}}>
        <h2 style={{marginTop:0}}>Kali-connected forensic acquisition</h2>
        <p>Connect the local Kali bridge to inventory disks and create a ddrescue image on a separately mounted destination drive. This action requires the companion to run with root privileges. Inventory does not write to disks.</p>
        <label className="vault-field"><span>Kali bridge pairing token</span><input type="password" autoComplete="off" value={bridgeToken} onChange={e=>{setBridgeToken(e.target.value);setPaired(false);}} placeholder="Paste token printed by the Kali bridge"/></label>
        <button className="network-run" type="button" onClick={pairKali} disabled={!bridgeToken.trim()||bridgeBusy}>{bridgeBusy?"Connecting…":"Connect and list drives"}</button>
        {paired&&<><div className="malware-kv"><span>Connection</span><strong>LOCAL KALI BRIDGE PAIRED</strong></div>
          <label className="vault-field"><span>Source device (choose the disk, not a mounted file)</span><select value={selectedDevice} onChange={e=>{setSelectedDevice(e.target.value);setConfirmationSource("");}}><option value="">Select a detected device</option>{devices.map(d=><option key={d.path} value={d.path}>{d.path} · {d.type} · {(d.size/1024/1024/1024).toFixed(2)} GB · {d.model||d.fstype||"storage"}{d.ro?" · read-only":""}</option>)}</select></label>
          <label className="vault-field"><span>Destination directory on a DIFFERENT physical drive</span><input value={destinationDirectory} onChange={e=>setDestinationDirectory(e.target.value)} placeholder="/mnt/backup"/></label>
          <label className="vault-field"><span>New image filename</span><input value={imageFilename} onChange={e=>setImageFilename(e.target.value)} placeholder="disk.img"/></label>
          <label className="vault-field"><span>Retype the exact source path to confirm</span><input value={confirmationSource} onChange={e=>setConfirmationSource(e.target.value)} placeholder="/dev/sdX"/></label>
          <button className="network-run" type="button" onClick={acquireImage} disabled={bridgeBusy||!selectedDevice||confirmationSource!==selectedDevice||!destinationDirectory.trim()||!imageFilename.trim()}>Create forensic image with ddrescue</button>
          {job&&<div className="malware-kv"><span>Acquisition job · {job.state}</span><strong>{job.message}</strong></div>}
          {job?.image&&<div className="malware-kv"><span>Image output</span><strong style={{overflowWrap:"anywhere"}}>{job.image}</strong></div>}
          {job?.map&&<div className="malware-kv"><span>ddrescue map</span><strong style={{overflowWrap:"anywhere"}}>{job.map}</strong></div>}
          {job?.state==="completed"&&<div style={{marginTop:18,borderTop:"1px solid var(--line)",paddingTop:14}}>
            <h3>Recover files from the forensic image</h3>
            <p>Foremost runs a fixed, allow-listed set of document, archive and picture signatures against the completed image. Output is written to a new folder on a drive separate from the original source.</p>
            <label className="vault-field"><span>Existing output parent directory on backup drive</span><input value={recoveryParent} onChange={e=>setRecoveryParent(e.target.value)} placeholder="/mnt/backup"/></label>
            <label className="vault-field"><span>Retype exact acquired image path</span><input value={confirmImage} onChange={e=>setConfirmImage(e.target.value)} placeholder={job.image}/></label>
            <button className="network-run" type="button" onClick={runForemost} disabled={bridgeBusy||confirmImage!==job.image}>Run Foremost on image</button>
            {recoveryJob&&<div className="malware-kv"><span>Foremost job · {recoveryJob.state}</span><strong>{recoveryJob.message}</strong></div>}
            {recoveryJob?.output&&<div className="malware-kv"><span>Recovered files folder</span><strong style={{overflowWrap:"anywhere"}}>{recoveryJob.output}</strong></div>}
            <p className="network-note">For PhotoRec's interactive recovery workflow, open another Kali terminal and run: <code>sudo photorec {job.image}</code>. In PhotoRec, select the image/partition, use File Opt to select formats, and choose an output folder on the backup drive. Do not choose the source drive.</p>
          </div>}
        </>}
        {bridgeMessage&&<p role="status" className="network-note">{bridgeMessage}</p>}
        <p className="network-note">Safety checks: exact source-path confirmation, existing destination directory, destination filesystem verification, different-device ancestry check, no overwrite, and a dedicated ddrescue map file. The original device is never used as the output target. Keep both drives connected until the job finishes.</p>
      </section>
      <section className="module-page-panel panel" style={{marginTop:18}}>
        <h2 style={{marginTop:0}}>1 / Select an evidence image</h2>
        <p>Choose a raw disk image, partition image or forensic export (maximum 256 MB for this browser-based first release). For physical media, create a forensic image using a write blocker before analysis.</p>
        <label className="vault-field"><span>Source image / evidence file</span><input type="file" accept=".img,.dd,.raw,.bin,.dmg,.001,.e01,application/octet-stream" onChange={choose}/></label>
        {source&&<div className="malware-kv"><span>Selected source</span><strong>{source.name} · {formatBytes(source.size)}</strong></div>}
        <button className="network-run" type="button" onClick={scan} disabled={!source||busy}>{busy?"Scanning locally…":"Scan for recoverable signatures"}</button>
        {message&&<p role="status" className="network-note">{message}</p>}
        {hash&&<div className="malware-kv"><span>Source SHA-256</span><strong style={{overflowWrap:"anywhere"}}>{hash}</strong></div>}
      </section>
      <section className="panel" style={{marginTop:14}}>
        <div className="panel-header"><div className="panel-title">2 / Recovery candidates</div><span className="panel-kicker">{items.length} FOUND · {formatBytes(total)}</span></div>
        <div className="panel-body">
          {!items.length?<div className="empty-state">No candidates yet. Select an evidence image and run a scan.</div>:<div className="activity-list">{items.map(item=><div className="activity-row" key={item.id}>{previewUrls[item.id]?<img src={previewUrls[item.id]} alt={`Preview of ${item.name}`} style={{width:72,height:56,objectFit:"contain",borderRadius:5,border:"1px solid var(--line)"}}/>:<div className="activity-bullet"/>}<div style={{minWidth:0,flex:1}}><div className="activity-name">{item.name} · {item.kind}</div><div className="activity-detail">Offset {item.start.toLocaleString()}–{item.end.toLocaleString()} · {formatBytes(item.size)}</div></div><button className="icon-button" type="button" aria-label={`Download ${item.name}`} onClick={()=>download(item)}><Download size={14}/></button></div>)}</div>}
        </div>
      </section>
      <section className="panel" style={{marginTop:14}}><div className="panel-header"><div className="panel-title"><FileSearch size={14} style={{display:"inline",marginRight:7}}/>Scope and limitations</div></div><div className="panel-body">
        <p>This first recovery slice performs simple signature-based carving of contiguous file data. It is not a full filesystem undelete engine and cannot reconstruct fragmented files, directory names, timestamps or original paths.</p>
        <p>SSD TRIM, overwritten sectors, encryption, filesystem metadata loss and damaged media can prevent recovery. A detected signature is only a candidate: open and validate each export before treating it as evidence.</p>
        <p>RAW camera formats, TIFF, archives and broader filesystem reconstruction are not included in this first slice. Large images and E01 containers require a dedicated forensic parser and are not decoded here.</p>
      </div></section>
      <div className="footer-note">LOCAL PROCESSING ONLY · SOURCE IMAGE IS NEVER MODIFIED · PRESERVE ORIGINAL EVIDENCE</div>
    </section>
  </main>;
}
