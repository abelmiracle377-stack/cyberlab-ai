"use client";
import {useState} from "react";
import Link from "next/link";
import {ArrowLeft,Code2,ShieldCheck,AlertTriangle,FileSearch} from "lucide-react";
type Result={fileName:string;size:number;sha256:string;entropy:number;metadata:Record<string,string|number>;note:string};
export default function ReverseEngineeringPage(){
 const [file,setFile]=useState<File|null>(null);const [result,setResult]=useState<Result|null>(null);const [error,setError]=useState("");const [busy,setBusy]=useState(false);
 async function inspect(){if(!file)return;setBusy(true);setError("");setResult(null);try{const form=new FormData();form.append("file",file);const response=await fetch("/api/reverse-engineering/inspect",{method:"POST",body:form});const data=await response.json();if(!response.ok)throw new Error(data.error||"Inspection failed.");setResult(data);}catch(cause){setError(cause instanceof Error?cause.message:"Unexpected inspection error.");}finally{setBusy(false);}}
 return <main className="agent-shell"><header className="agent-topbar"><Link href="/" className="agent-back"><ArrowLeft size={14}/> Dashboard</Link><div className="agent-brand"><Code2 size={16}/> CYBERLAB AI <span className="agent-top-sep">/</span> REVERSE ENGINEERING</div><span className="agent-secure-label"><span/> STATIC INSPECTION</span></header>
 <section className="agent-main"><div className="agent-heading"><div className="agent-overline">BINARY RESEARCH / 009</div><h1>Binary header inspector</h1><p>Inspect PE, ELF and Mach-O executable headers, architecture hints, file hash and entropy.</p></div>
 <div className="scope-warning"><AlertTriangle size={14}/>Static inspection only. Do not execute unknown files. Maximum file size: 4 MB.</div>
 <div className="network-upload"><div className="network-upload-icon"><FileSearch size={22}/></div><h2>Select a binary</h2><p>Supported formats: Windows PE, Linux ELF and macOS Mach-O.</p><label className="network-file"><input type="file" onChange={e=>{setFile(e.target.files?.[0]||null);setResult(null);setError("");}}/>Choose file</label>{file&&<div className="network-filename">{file.name} · {(file.size/1024).toFixed(1)} KB</div>}<button className="network-run" onClick={inspect} disabled={!file||busy}>{busy?"Inspecting…":"Inspect headers"}</button></div>
 {error&&<div className="agent-error"><AlertTriangle size={14}/>{error}</div>}
 {result&&<div className="malware-results"><h2>Binary metadata</h2><div className="malware-kv"><span>File</span><strong>{result.fileName}</strong></div><div className="malware-kv"><span>Size</span><strong>{result.size.toLocaleString()} bytes</strong></div><div className="malware-kv"><span>SHA-256</span><strong className="malware-hash">{result.sha256}</strong></div><div className="malware-kv"><span>Entropy</span><strong>{result.entropy} / 8</strong></div>{Object.entries(result.metadata).map(([key,value])=><div className="malware-kv" key={key}><span>{key}</span><strong>{String(value)}</strong></div>)}<p>{result.note}</p></div>}
 <div className="agent-disclaimer"><ShieldCheck size={12}/> Header inspection is not full disassembly or behavioural analysis. Use dedicated reverse-engineering tools in an isolated lab for deeper research.</div>
 </section></main>;
}
