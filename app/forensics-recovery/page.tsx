"use client";

import { useEffect, useMemo, useState, type ChangeEvent } from "react";
import Link from "next/link";
import { ArrowLeft, Download, FileSearch, HardDriveDownload, ShieldCheck } from "lucide-react";

type Kind = "JPEG" | "PNG" | "GIF" | "PDF";
type Recovered = { id:string; kind:Kind; start:number; end:number; size:number; name:string };
type BlockDevice = {name:string;path:string;type:string;size:number;ro:boolean;tran?:string;model?:string;fstype?:string;mountpoints?:Array<string|null>};
type AcquisitionJob = {id:string;state:string;source:string;image:string;map:string;output?:string;message:string;return_code?:number;manifest?:{path:string;files_hashed:number;total_bytes_hashed:number;truncated:boolean}};
type ImageProbe = {recognized:boolean;metadata:Record<string,string>;method:string;note:string};
type ImagePartitions = {partitions:Array<{slot:string;start_sector:number;end_sector:number;length_sectors:number;description:string}>;partition_count:number;method:string;note:string};
type FilesystemDetails = {partition:{slot:string;start_sector:number;end_sector:number;length_sectors:number;description:string};metadata:string;truncated:boolean;method:string;note:string};
type DeletedFile = {inode:string;path:string;deleted:boolean;isDirectory:boolean};
type RecoveredFile = {inode:string;destination:string;size_bytes:number;sha256:string;note:string};
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
const MAX_SIGNATURE_OFFSETS = 10000;
function findOffsets(data:Uint8Array, patterns:number[][]):number[]{
  const offsets:number[]=[];
  for(const pattern of patterns){
    let cursor=0;
    while(offsets.length<MAX_SIGNATURE_OFFSETS){
      const found=findBytes(data,pattern,cursor);
      if(found<0)break;
      offsets.push(found);
      cursor=found+1;
    }
    if(offsets.length>=MAX_SIGNATURE_OFFSETS)break;
  }
  return offsets.sort((a,b)=>a-b);
}
function pairSignatures(data:Uint8Array, starts:number[][], endPattern:number[], kind:Kind):Recovered[]{
  const startOffsets=findOffsets(data,starts),endOffsets=findOffsets(data,[endPattern]);
  const found:Recovered[]=[];
  let endIndex=0;
  for(let startIndex=0;startIndex<startOffsets.length&&endIndex<endOffsets.length;startIndex++){
    const start=startOffsets[startIndex];
    while(endIndex<endOffsets.length&&endOffsets[endIndex]<start+starts[0].length)endIndex++;
    if(endIndex>=endOffsets.length)break;
    const end=endOffsets[endIndex]+endPattern.length;
    if(end>start&&end<=data.length){
      found.push({id:`${kind}-${start}-${end}`,kind,start,end,size:end-start,name:`recovered-${String(found.length+1).padStart(3,"0")}.${kind==="JPEG"?"jpg":kind.toLowerCase()}`});
      while(startIndex+1<startOffsets.length&&startOffsets[startIndex+1]<end)startIndex++;
      endIndex++;
    }
  }
  return found;
}
function carve(data:Uint8Array):Recovered[]{
  const candidates=[
    ...pairSignatures(data,[signatures.jpegStart],signatures.jpegEnd,"JPEG"),
    ...pairSignatures(data,[signatures.pngStart],signatures.pngEnd,"PNG"),
    ...pairSignatures(data,[signatures.gif87,signatures.gif89],[0x3b],"GIF"),
    ...pairSignatures(data,[signatures.pdf],signatures.pdfEnd,"PDF")
  ].sort((a,b)=>a.start-b.start||a.end-b.end);
  const accepted:Recovered[]=[];
  let lastEnd=-1;
  for(const item of candidates){
    if(item.start<lastEnd)continue;
    const index=accepted.length;
    item.name=`recovered-${String(index+1).padStart(3,"0")}.${item.kind==="JPEG"?"jpg":item.kind.toLowerCase()}`;
    item.id=`${item.kind}-${item.start}-${item.end}`;
    accepted.push(item);
    lastEnd=item.end;
  }
  return accepted;
}
function flattenBlockDevices(nodes:BlockDevice[]):BlockDevice[]{
  return nodes.flatMap(node=>[node,...flattenBlockDevices(((node as any).children||[]) as BlockDevice[])]);
}
function formatBytes(n:number){return n<1024?`${n} B`:n<1024*1024?`${(n/1024).toFixed(1)} KB`:`${(n/1024/1024).toFixed(2)} MB`;}

export default function ForensicsRecoveryPage(){
  const [source,setSource]=useState<File|null>(null),[items,setItems]=useState<Recovered[]>([]),[previewUrls,setPreviewUrls]=useState<Record<string,string>>({}),[busy,setBusy]=useState(false),[message,setMessage]=useState(""),[hash,setHash]=useState("");
  const [bridgeToken,setBridgeToken]=useState(""),[paired,setPaired]=useState(false),[devices,setDevices]=useState<BlockDevice[]>([]),[selectedDevice,setSelectedDevice]=useState(""),[destinationDirectory,setDestinationDirectory]=useState("/mnt/backup"),[imageFilename,setImageFilename]=useState("cyberlab-disk.img"),[confirmationSource,setConfirmationSource]=useState(""),[bridgeBusy,setBridgeBusy]=useState(false),[bridgeMessage,setBridgeMessage]=useState(""),[job,setJob]=useState<AcquisitionJob|null>(null),[recoveryParent,setRecoveryParent]=useState("/mnt/backup"),[confirmImage,setConfirmImage]=useState(""),[recoveryJob,setRecoveryJob]=useState<AcquisitionJob|null>(null),[imageProbe,setImageProbe]=useState<ImageProbe|null>(null),[probeBusy,setProbeBusy]=useState(false),[imagePartitions,setImagePartitions]=useState<ImagePartitions|null>(null),[partitionsBusy,setPartitionsBusy]=useState(false),[selectedPartition,setSelectedPartition]=useState(""),[filesystemDetails,setFilesystemDetails]=useState<FilesystemDetails|null>(null),[filesystemBusy,setFilesystemBusy]=useState(false);
  const [deletedFiles,setDeletedFiles]=useState<DeletedFile[]|null>(null),[deletedBusy,setDeletedBusy]=useState(false),[recoveringInode,setRecoveringInode]=useState(""),[recoveredFiles,setRecoveredFiles]=useState<RecoveredFile[]>([]);
  const [carveTypes,setCarveTypes]=useState(""),[bulkBusy,setBulkBusy]=useState(false),[bulkResult,setBulkResult]=useState<{recovered_count:number;failed_count:number;deleted_found:number;output:string}|null>(null);
  const [artifactPath,setArtifactPath]=useState(""),[artifactBusy,setArtifactBusy]=useState(""),[plistResult,setPlistResult]=useState<{format:string;top_level_type:string;top_level_keys:string[];content:unknown}|null>(null),[sqliteResult,setSqliteResult]=useState<{table_count:number;tables:{name:string;columns:string[];row_count:number|null}[]}|null>(null),[tableRows,setTableRows]=useState<{table:string;columns:string[];rows:unknown[][]}|null>(null);
  useEffect(()=>()=>{Object.values(previewUrls).forEach(url=>URL.revokeObjectURL(url));},[previewUrls]);
  const total=useMemo(()=>items.reduce((sum,x)=>sum+x.size,0),[items]);
  async function pairKali(){
    setBridgeBusy(true);setBridgeMessage("");setPaired(false);
    try{
      const headers={Authorization:"Bearer "+bridgeToken.trim()};
      const health=await fetch("/api/kali/health",{headers,cache:"no-store"});
      const h=await health.json();if(!health.ok)throw new Error(h.error||"Could not connect to Kali.");
      const inventory=await fetch("/api/kali/forensics/devices",{headers,cache:"no-store"});
      const d=await inventory.json();if(!inventory.ok)throw new Error(d.error||"Could not read block-device inventory.");
      setDevices(flattenBlockDevices((d.devices||[]) as BlockDevice[]).filter((item:BlockDevice)=>item.path&&["disk","part"].includes(item.type)));
      setPaired(true);setBridgeMessage("Kali connected. Device inventory is read-only; no drive has been mounted or modified.");
    }catch(e){setBridgeMessage(e instanceof Error?e.message:"Kali connection failed.");}
    finally{setBridgeBusy(false);}
  }
  async function refreshDevices(){
    const response=await fetch("/api/kali/forensics/devices",{headers:{Authorization:"Bearer "+bridgeToken.trim()},cache:"no-store"});
    const data=await response.json();if(!response.ok)throw new Error(data.error||"Device inventory failed.");
    setDevices(flattenBlockDevices((data.devices||[]) as BlockDevice[]).filter((item:BlockDevice)=>item.path&&["disk","part"].includes(item.type)));
  }
  async function inspectImage(){
    if(!job||job.state!=="completed"||confirmImage!==job.image){setBridgeMessage("Confirm the exact completed image path before inspection.");return;}
    setProbeBusy(true);setImageProbe(null);
    try{
      const response=await fetch("/api/kali/forensics/inspect",{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+bridgeToken.trim()},body:JSON.stringify({imageJobId:job.id,confirmationImage:confirmImage})});
      const data=await response.json();if(!response.ok)throw new Error(data.error||"Image inspection failed.");
      setImageProbe(data);setBridgeMessage(data.note||"Read-only image inspection completed.");
    }catch(e){setBridgeMessage(e instanceof Error?e.message:"Image inspection failed.");}
    finally{setProbeBusy(false);}
  }
  async function inspectPartitions(){
    if(!job||job.state!=="completed"||confirmImage!==job.image){setBridgeMessage("Confirm the exact completed image path before partition analysis.");return;}
    setPartitionsBusy(true);setImagePartitions(null);
    try{
      const response=await fetch("/api/kali/forensics/partitions",{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+bridgeToken.trim()},body:JSON.stringify({imageJobId:job.id,confirmationImage:confirmImage})});
      const data=await response.json();if(!response.ok)throw new Error(data.error||"Partition analysis failed.");
      setImagePartitions(data);setBridgeMessage(data.note||"Read-only partition analysis completed.");
    }catch(e){setBridgeMessage(e instanceof Error?e.message:"Partition analysis failed.");}
    finally{setPartitionsBusy(false);}
  }
  async function inspectPartitionFilesystem(){
    const startSector=Number(selectedPartition);
    if(!job||job.state!=="completed"||confirmImage!==job.image||!selectedPartition){setBridgeMessage("Select a discovered partition and confirm the exact image path.");return;}
    setFilesystemBusy(true);setFilesystemDetails(null);
    try{
      const response=await fetch("/api/kali/forensics/fsstat",{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+bridgeToken.trim()},body:JSON.stringify({imageJobId:job.id,confirmationImage:confirmImage,startSector})});
      const data=await response.json();if(!response.ok)throw new Error(data.error||"Filesystem metadata inspection failed.");
      setFilesystemDetails(data);setBridgeMessage(data.note||"Read-only filesystem metadata inspection completed.");
    }catch(e){setBridgeMessage(e instanceof Error?e.message:"Filesystem metadata inspection failed.");}
    finally{setFilesystemBusy(false);}
  }
  async function startCarveJob(endpoint:string,extra:Record<string,unknown>,label:string){
    if(!job||job.state!=="completed"||confirmImage!==job.image){setBridgeMessage("Confirm the exact completed image path before starting recovery.");return;}
    setBridgeBusy(true);
    try{
      const response=await fetch("/api/kali"+endpoint,{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+bridgeToken.trim()},body:JSON.stringify({imageJobId:job.id,outputDirectory:recoveryParent,confirmationImage:confirmImage,...extra})});
      const data=await response.json();if(!response.ok)throw new Error(data.error||(label+" could not start."));
      setRecoveryJob(data.job);setBridgeMessage(data.note||(label+" started."));
      const id=data.job.id;
      const poll=async():Promise<void>=>{
        const status=await fetch("/api/kali/forensics/jobs/"+id,{headers:{Authorization:"Bearer "+bridgeToken.trim()},cache:"no-store"});
        const payload=await status.json();if(!status.ok)throw new Error(payload.error||"Could not read recovery status.");
        setRecoveryJob(payload.job);
        if(payload.job.state==="running"){await new Promise(resolve=>setTimeout(resolve,3000));return poll();}
        setBridgeMessage(payload.job.message||"Recovery job finished.");
      };
      void poll().catch(e=>setBridgeMessage(e instanceof Error?e.message:"Could not monitor recovery job."));
    }catch(e){setBridgeMessage(e instanceof Error?e.message:(label+" failed."));}
    finally{setBridgeBusy(false);}
  }
  function runForemost(){const extra=carveTypes.trim()?{fileTypes:carveTypes.trim()}:{};void startCarveJob("/forensics/foremost",extra,"Foremost recovery");}
  function runPhotorec(){void startCarveJob("/forensics/photorec",{},"PhotoRec carving");}
  async function recoverAllDeleted(){
    if(!job||job.state!=="completed"||confirmImage!==job.image){setBridgeMessage("Confirm the exact completed image path first.");return;}
    const offset=selectedPartition?Number(selectedPartition):0;
    setBulkBusy(true);setBulkResult(null);
    try{
      const response=await fetch("/api/kali/forensics/recover-all-deleted",{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+bridgeToken.trim()},body:JSON.stringify({imageJobId:job.id,confirmationImage:confirmImage,outputDirectory:recoveryParent,offset,maxFiles:200})});
      const data=await response.json();if(!response.ok)throw new Error(data.error||"Bulk undelete failed.");
      setBulkResult(data);setBridgeMessage("Recovered "+data.recovered_count+" of "+data.deleted_found+" deleted files to "+data.output+(data.failed_count?(" ("+data.failed_count+" failed)"):""));
    }catch(e){setBridgeMessage(e instanceof Error?e.message:"Bulk undelete failed.");}
    finally{setBulkBusy(false);}
  }
  async function listDeleted(){
    if(!job||job.state!=="completed"||confirmImage!==job.image){setBridgeMessage("Confirm the exact completed image path first.");return;}
    const offset=selectedPartition?Number(selectedPartition):0;
    setDeletedBusy(true);setRecoveredFiles([]);
    try{
      const response=await fetch("/api/kali/forensics/deleted-list",{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+bridgeToken.trim()},body:JSON.stringify({imageJobId:job.id,confirmationImage:confirmImage,offset,limit:1000})});
      const data=await response.json();if(!response.ok)throw new Error(data.error||"Could not list deleted files.");
      setDeletedFiles(data.deleted_files||[]);setBridgeMessage(data.note||"Deleted-file listing complete.");
    }catch(e){setBridgeMessage(e instanceof Error?e.message:"Deleted-file listing failed.");}
    finally{setDeletedBusy(false);}
  }
  async function recoverDeleted(file:DeletedFile){
    if(!job||confirmImage!==job.image)return;
    const offset=selectedPartition?Number(selectedPartition):0;
    const name=file.path.split("/").pop()||file.inode;
    setRecoveringInode(file.inode);
    try{
      const response=await fetch("/api/kali/forensics/recover-file",{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+bridgeToken.trim()},body:JSON.stringify({imageJobId:job.id,confirmationImage:confirmImage,inode:file.inode,outputDirectory:recoveryParent,offset,filename:name})});
      const data=await response.json();if(!response.ok)throw new Error(data.error||"File recovery failed.");
      setRecoveredFiles(current=>[data,...current]);setBridgeMessage("Recovered "+name+" ("+data.size_bytes+" bytes) to "+data.destination);
    }catch(e){setBridgeMessage(e instanceof Error?e.message:"File recovery failed.");}
    finally{setRecoveringInode("");}
  }
  async function acquireImage(){
    if(!selectedDevice||confirmationSource!==selectedDevice){setBridgeMessage("Select a source and retype its exact device path to confirm.");return;}
    setBridgeBusy(true);setBridgeMessage("Submitting protected imaging job…");
    try{
      const response=await fetch("/api/kali/forensics/image",{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+bridgeToken.trim()},body:JSON.stringify({source:selectedDevice,destinationDirectory,filename:imageFilename,confirmationSource})});
      const data=await response.json();if(!response.ok)throw new Error(data.error||"Disk imaging could not start.");
      setJob(data.job);setBridgeMessage(data.note||"Disk imaging started.");
      const jobId=data.job.id;
      const poll=async():Promise<void>=>{
        const status=await fetch("/api/kali/forensics/jobs/"+jobId,{headers:{Authorization:"Bearer "+bridgeToken.trim()},cache:"no-store"});
        const payload=await status.json();if(!status.ok)throw new Error(payload.error||"Could not read imaging status.");
        setJob(payload.job);
        if(payload.job.state==="running"){await new Promise(resolve=>setTimeout(resolve,3000));return poll();}
        setBridgeMessage(payload.job.message||"Imaging job finished.");
      };
      void poll().catch(e=>setBridgeMessage(e instanceof Error?e.message:"Could not monitor imaging job."));
    }catch(e){setBridgeMessage(e instanceof Error?e.message:"Disk imaging failed.");}
    finally{setBridgeBusy(false);}
  }
  async function postBridge(endpoint:string,body:Record<string,unknown>){
    const response=await fetch("/api/kali"+endpoint,{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+bridgeToken.trim()},body:JSON.stringify(body)});
    const data=await response.json();if(!response.ok)throw new Error(data.error||"Request failed.");return data;
  }
  async function parsePlist(){
    if(!artifactPath.trim()){setMessage("Enter the path to a .plist file on the companion.");return;}
    setArtifactBusy("plist");setPlistResult(null);setSqliteResult(null);setTableRows(null);
    try{setPlistResult(await postBridge("/forensics/plist-parse",{path:artifactPath.trim()}));}
    catch(e){setMessage(e instanceof Error?e.message:"Plist parse failed.");}finally{setArtifactBusy("");}
  }
  async function inspectSqlite(){
    if(!artifactPath.trim()){setMessage("Enter the path to a SQLite database on the companion.");return;}
    setArtifactBusy("sqlite");setPlistResult(null);setTableRows(null);
    try{setSqliteResult(await postBridge("/forensics/sqlite-inspect",{path:artifactPath.trim()}));}
    catch(e){setMessage(e instanceof Error?e.message:"SQLite inspect failed.");}finally{setArtifactBusy("");}
  }
  async function sampleTable(table:string){
    setArtifactBusy("row-"+table);setTableRows(null);
    try{setTableRows(await postBridge("/forensics/sqlite-sample",{path:artifactPath.trim(),table,limit:50}));}
    catch(e){setMessage(e instanceof Error?e.message:"Table sample failed.");}finally{setArtifactBusy("");}
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
        <h2 style={{marginTop:0}}>Kali / CyberLab AI OS forensic acquisition</h2>
        <p>Connect the local Kali or CyberLab AI OS Linux runner to inventory disks and create a ddrescue image on a separately mounted destination drive. This action requires the companion to run with root privileges. Inventory does not write to disks.</p>
        <label className="vault-field"><span>Kali bridge pairing token</span><input type="password" autoComplete="off" value={bridgeToken} onChange={e=>{setBridgeToken(e.target.value);setPaired(false);}} placeholder="Paste token printed by the Kali bridge"/></label>
        <button className="network-run" type="button" onClick={pairKali} disabled={!bridgeToken.trim()||bridgeBusy}>{bridgeBusy?"Connecting…":"Connect and list drives"}</button>
        {paired&&<><div className="malware-kv"><span>Connection</span><strong>LOCAL KALI BRIDGE PAIRED</strong></div>
          <label className="vault-field"><span>Source device (choose the disk, not a mounted file)</span><select value={selectedDevice} onChange={e=>{setSelectedDevice(e.target.value);setConfirmationSource("");}}><option value="">Select a detected device</option>{devices.map(d=>{const mounted=Boolean(d.mountpoints?.some(Boolean));return <option key={d.path} value={d.path} disabled={mounted}>{d.path} · {d.type} · {(d.size/1024/1024/1024).toFixed(2)} GB · {d.model||d.fstype||"storage"}{d.ro?" · read-only":""}{mounted?" · MOUNTED — unavailable":""}</option>})}</select></label>
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
            <label className="vault-field"><span>Carve file types (optional, comma-separated: jpg,png,pdf,mov,zip… blank = broad default)</span><input value={carveTypes} onChange={e=>setCarveTypes(e.target.value)} placeholder="jpg,png,gif,mov,avi,pdf,doc,zip" /></label>
            <button className="network-run" type="button" onClick={runForemost} disabled={bridgeBusy||confirmImage!==job.image}>Run Foremost on image</button>
            <button className="network-run" type="button" onClick={runPhotorec} disabled={bridgeBusy||confirmImage!==job.image} style={{marginTop:8}}>Run PhotoRec carving (480+ formats: HEIC, RAW, MP4, Office…)</button>
            <button className="network-run" type="button" onClick={inspectImage} disabled={probeBusy||confirmImage!==job.image} style={{marginTop:8}}>{probeBusy?"Inspecting image…":"Identify filesystem (read-only)"}</button>
            <button className="network-run" type="button" onClick={inspectPartitions} disabled={partitionsBusy||confirmImage!==job.image} style={{marginTop:8}}>{partitionsBusy?"Analysing partitions…":"Analyse partition table (read-only)"}</button>
            {imagePartitions&&imagePartitions.partition_count>0&&<><label className="vault-field"><span>Partition for filesystem metadata inspection</span><select value={selectedPartition} onChange={e=>{setSelectedPartition(e.target.value);setFilesystemDetails(null);}}><option value="">Select a discovered partition</option>{imagePartitions.partitions.map(part=><option key={part.slot} value={String(part.start_sector)}>Slot {part.slot} · sector {part.start_sector.toLocaleString()} · {part.description}</option>)}</select></label><button className="network-run" type="button" onClick={inspectPartitionFilesystem} disabled={filesystemBusy||!selectedPartition||confirmImage!==job.image} style={{marginTop:8}}>{filesystemBusy?"Inspecting filesystem…":"Inspect selected filesystem metadata (read-only)"}</button></>}
            {filesystemDetails&&<><div className="malware-kv"><span>Filesystem metadata · slot {filesystemDetails.partition.slot}</span><strong>{filesystemDetails.partition.description}</strong></div><pre style={{whiteSpace:"pre-wrap",overflowWrap:"anywhere",maxHeight:360,overflowY:"auto",fontSize:12,padding:12,background:"var(--panel)",border:"1px solid var(--line)",borderRadius:6}}>{filesystemDetails.metadata}</pre>{filesystemDetails.truncated&&<p className="network-note">Output was truncated to 12,000 characters.</p>}<p className="network-note">{filesystemDetails.note}</p></>}
            {imagePartitions&&<><div className="malware-kv"><span>Allocated partitions</span><strong>{imagePartitions.partition_count}</strong></div>{imagePartitions.partitions.map(part=><div className="malware-kv" key={part.slot}><span>Slot {part.slot} · sectors {part.start_sector.toLocaleString()}–{part.end_sector.toLocaleString()} · {part.length_sectors.toLocaleString()} sectors</span><strong>{part.description}</strong></div>)}<p className="network-note">{imagePartitions.note}</p></>}
            {imageProbe&&<><div className="malware-kv"><span>Filesystem signature</span><strong>{imageProbe.recognized?"RECOGNISED":"NO SIGNATURE RECOGNISED"}</strong></div>{Object.entries(imageProbe.metadata).map(([key,value])=><div className="malware-kv" key={key}><span>{key.toUpperCase()}</span><strong>{value}</strong></div>)}<p className="network-note">{imageProbe.note}</p></>}
            {recoveryJob&&<div className="malware-kv"><span>Foremost job · {recoveryJob.state}</span><strong>{recoveryJob.message}</strong></div>}
            {recoveryJob?.output&&<div className="malware-kv"><span>Recovered files folder</span><strong style={{overflowWrap:"anywhere"}}>{recoveryJob.output}</strong></div>}
            {recoveryJob?.manifest&&<><div className="malware-kv"><span>SHA-256 manifest</span><strong style={{overflowWrap:"anywhere"}}>{recoveryJob.manifest.path}</strong></div><p className="network-note">Manifest hashes {recoveryJob.manifest.files_hashed.toLocaleString()} recovered file(s), covering {formatBytes(recoveryJob.manifest.total_bytes_hashed)}.{recoveryJob.manifest.truncated?" File limit reached; manifest is partial.":" All enumerated regular files were hashed."}</p></>}
            <div style={{marginTop:16,borderTop:"1px solid var(--line)",paddingTop:12}}>
              <h3>Deleted-file recovery (filesystem-aware)</h3>
              <p>Sleuth Kit lists files deleted from the filesystem with their original names and paths, then recovers them to the backup drive. This complements carving when the filesystem is intact. Select a partition above to scope the listing to it.</p>
              <button className="network-run" type="button" onClick={recoverAllDeleted} disabled={bulkBusy||confirmImage!==job.image}>{bulkBusy?"Recovering all deleted files…":"Recover ALL deleted files in one go (keeps names)"}</button>
              {bulkResult&&<p className="network-note">Recovered {bulkResult.recovered_count} of {bulkResult.deleted_found} deleted files{bulkResult.failed_count?(" ("+bulkResult.failed_count+" failed)"):""} to {bulkResult.output}. Each file is SHA-256 hashed; validate before trusting.</p>}
              <button className="network-run" type="button" onClick={listDeleted} disabled={deletedBusy||confirmImage!==job.image} style={{marginTop:8}}>{deletedBusy?"Listing deleted files…":"List deleted files (recover individually)"}</button>
              {deletedFiles&&<><div className="malware-kv"><span>Deleted entries{selectedPartition?" · sector "+Number(selectedPartition).toLocaleString():""}</span><strong>{deletedFiles.length}</strong></div>
                <div style={{maxHeight:320,overflowY:"auto",border:"1px solid var(--line)",borderRadius:6,marginTop:8}}>
                  {deletedFiles.filter(f=>!f.isDirectory).map(f=><div key={f.inode+f.path} style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:8,padding:"6px 10px",borderBottom:"1px solid var(--line)"}}>
                    <span style={{overflowWrap:"anywhere",fontSize:12}}>{f.path}</span>
                    <button className="network-run" type="button" onClick={()=>recoverDeleted(f)} disabled={recoveringInode===f.inode} style={{flexShrink:0}}>{recoveringInode===f.inode?"Recovering…":"Recover"}</button>
                  </div>)}
                  {deletedFiles.filter(f=>!f.isDirectory).length===0&&<p className="network-note" style={{padding:10}}>No deleted files were listed for this scope. Try a different partition, or use carving for a damaged filesystem.</p>}
                </div></>}
              {recoveredFiles.length>0&&<><div className="malware-kv" style={{marginTop:10}}><span>Recovered this session</span><strong>{recoveredFiles.length}</strong></div>{recoveredFiles.map(r=><div className="malware-kv" key={r.destination}><span style={{overflowWrap:"anywhere"}}>{r.destination.split("/").pop()} · {formatBytes(r.size_bytes)}</span><strong style={{overflowWrap:"anywhere",fontSize:11}}>{r.sha256.slice(0,16)}…</strong></div>)}<p className="network-note">Each recovered file is written with owner-only permissions to a separate drive and SHA-256 hashed. Validate every file before trusting it; recovered data can be partial.</p></>}
            </div>
            <p className="network-note">PhotoRec carving runs from the button above — it signature-recovers 480+ formats (including HEIC, camera RAW, MP4 and Office files) directly from this verified image to a new folder on the backup drive, never the source. Use it when the filesystem is damaged or reformatted and named undelete finds nothing.</p>
          </div>}
        </>}
        {bridgeMessage&&<p role="status" className="network-note">{bridgeMessage}</p>}
        <p className="network-note">Mounted source partitions are marked unavailable in the selector; the bridge independently checks the full source device tree and rejects any mounted source partition. Safety checks: exact source-path confirmation, existing destination directory, destination filesystem verification, different-device ancestry check, no overwrite, and a dedicated ddrescue map file. The original device is never used as the output target. Keep both drives connected until the job finishes.</p>
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
      <section className="panel" style={{marginTop:14}}>
        <div className="panel-header"><div className="panel-title"><FileSearch size={14} style={{display:"inline",marginRight:7}}/>Artifact inspection · plist / SQLite</div><span className="panel-kicker">READ-ONLY</span></div>
        <div className="panel-body">
          <p>Parse a recovered artifact on the companion read-only: Apple property lists (binary or XML) and SQLite databases (browser history, cookies, logins). Point to a file path on the companion machine — for example one recovered to your backup drive above.</p>
          <label className="vault-field"><span>Artifact file path (on the companion)</span><input value={artifactPath} onChange={e=>setArtifactPath(e.target.value)} placeholder="/mnt/backup/recovered/History  or  …/com.apple.Safari.plist"/></label>
          <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
            <button className="network-run" type="button" onClick={parsePlist} disabled={artifactBusy==="plist"}>{artifactBusy==="plist"?"Parsing…":"Parse as plist"}</button>
            <button className="network-run" type="button" onClick={inspectSqlite} disabled={artifactBusy==="sqlite"}>{artifactBusy==="sqlite"?"Inspecting…":"Inspect as SQLite"}</button>
          </div>
          {plistResult&&<div className="network-note"><strong>{plistResult.format} plist · {plistResult.top_level_type}</strong><div style={{marginTop:6}}>Keys: {plistResult.top_level_keys.join(", ")||"—"}</div><pre style={{whiteSpace:"pre-wrap",wordBreak:"break-word",maxHeight:260,overflow:"auto",marginTop:6}}>{JSON.stringify(plistResult.content,null,2).slice(0,4000)}</pre></div>}
          {sqliteResult&&<div className="network-note"><strong>{sqliteResult.table_count} tables</strong><div className="activity-list" style={{marginTop:6}}>{sqliteResult.tables.map(t=><div className="activity-row" key={t.name}><div style={{minWidth:0,flex:1}}><div className="activity-name">{t.name} · {t.row_count??"?"} rows</div><div className="activity-detail">{t.columns.join(", ")}</div></div><button className="icon-button" type="button" onClick={()=>sampleTable(t.name)} disabled={artifactBusy==="row-"+t.name}>{artifactBusy==="row-"+t.name?"…":"Sample"}</button></div>)}</div></div>}
          {tableRows&&<div className="network-note"><strong>{tableRows.table}</strong> · {tableRows.columns.join(", ")}<pre style={{whiteSpace:"pre-wrap",wordBreak:"break-word",maxHeight:240,overflow:"auto",marginTop:6}}>{tableRows.rows.map(r=>JSON.stringify(r)).join("\n").slice(0,4000)}</pre></div>}
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
