"use client";
import { useState } from "react";
import Link from "next/link";
import { ArrowLeft, Code2, ShieldCheck, AlertTriangle, FileCode2 } from "lucide-react";

type Detail={format:string;architecture:string;endianness:string;sections:string;timestamp:string;entryPoint:string;subsystem:string;note:string};
function inspect(buffer:ArrayBuffer):Detail{
 const view=new DataView(buffer);const bytes=new Uint8Array(buffer);
 const hex=(start:number,count:number)=>[...bytes.slice(start,start+count)].map(x=>x.toString(16).padStart(2,"0")).join(" ");
 if(bytes.length>=64&&view.getUint16(0,true)===0x5a4d){
  const offset=view.getUint32(0x3c,true);
  if(offset+24>bytes.length||view.getUint32(offset,true)!==0x4550)throw new Error("MZ header found, but the PE header is invalid or outside this file.");
  const machine=view.getUint16(offset+4,true);const sections=view.getUint16(offset+6,true);const stamp=view.getUint32(offset+8,true);const optionalSize=view.getUint16(offset+20,true);
  const magic=offset+24+2<=bytes.length?view.getUint16(offset+24,true):0;
  const subsystem=offset+24+70<=bytes.length?view.getUint16(offset+24+68,true):0;
  const machines:Record<number,string>={0x14c:"x86 (32-bit)",0x8664:"x86-64 (AMD64)",0x1c0:"ARM",0x1c4:"ARMv7",0xaa64:"ARM64"};
  const subsystems:Record<number,string>={1:"Native",2:"Windows GUI",3:"Windows console",5:"OS/2 console",9:"Windows CE GUI",10:"EFI application",16:"Windows boot application"};
  return {format:"Portable Executable (PE)",architecture:machines[machine]||"Unknown (0x"+machine.toString(16)+")",endianness:"Little-endian",sections:String(sections),timestamp:stamp?new Date(stamp*1000).toISOString():"Not set",entryPoint:"RVA is in optional header (not decoded in this view)",subsystem:subsystems[subsystem]||"Unknown ("+subsystem+")",note:"Static header inspection only. Section contents, imports and runtime behaviour are not analysed."};
 }
 if(bytes.length>=52&&bytes[0]===0x7f&&bytes[1]===0x45&&bytes[2]===0x4c&&bytes[3]===0x46){
  const cls=bytes[4];const data=bytes[5];if(![1,2].includes(cls)||![1,2].includes(data))throw new Error("ELF class or byte order is invalid.");
  const little=data===1;const machine=view.getUint16(18,little);const entry=cls===2?view.getBigUint64(24,little):BigInt(view.getUint32(24,little));
  const machines:Record<number,string>={3:"x86 (32-bit)",40:"ARM",62:"x86-64 (AMD64)",183:"AArch64",243:"RISC-V"};
  return {format:"Executable and Linkable Format (ELF)",architecture:machines[machine]||"Unknown (e_machine "+machine+")",endianness:little?"Little-endian":"Big-endian",sections:"Section table not decoded",timestamp:"Not present in ELF header",entryPoint:"0x"+entry.toString(16),subsystem:"OS ABI: "+bytes[7],note:"Static ELF header inspection only. No code is executed and no disassembly is performed."};
 }
 const magic=hex(0,4);
 if(["fe ed fa ce","fe ed fa cf","ce fa ed fe","cf fa ed fe","ca fe ba be","be ba fe ca"].includes(magic))return {format:"Mach-O / Universal binary",architecture:"Inspect architecture slices with a dedicated offline parser",endianness:"Determined by file magic",sections:"Not decoded",timestamp:"Not decoded",entryPoint:"Not decoded",subsystem:"Not decoded",note:"Recognised Mach-O magic only. This view does not parse load commands or execute code."};
 throw new Error("Unsupported or unrecognised format. This inspector currently supports PE, ELF and Mach-O headers.");
}
export default function ReverseEngineeringPage(){
 const [file,setFile]=useState<File|null>(null);const [detail,setDetail]=useState<Detail|null>(null);const [error,setError]=useState("");const [busy,setBusy]=useState(false);
 async function analyse(){if(!file)return;if(file.size>10*1024*1024){setError("File exceeds the 10 MB limit.");return;}setBusy(true);setError("");setDetail(null);try{setDetail(inspect(await file.arrayBuffer()));}catch(e){setError(e instanceof Error?e.message:"Could not inspect this file.");}finally{setBusy(false);}}
 return <main className="agent-shell">
  <header className="agent-topbar"><Link href="/" className="agent-back"><ArrowLeft size={14}/> Dashboard</Link><div className="agent-brand"><Code2 size={16}/> CYBERLAB AI <span className="agent-top-sep">/</span> REVERSE ENGINEERING</div><span className="agent-secure-label"><span/> LOCAL HEADER INSPECTION</span></header>
  <section className="agent-main">
   <div className="agent-heading"><div className="agent-overline">BINARY FORMAT RESEARCH / 006</div><h1>Binary header inspector</h1><p>Identify PE, ELF and Mach-O formats and inspect selected executable header metadata locally in your browser.</p></div>
   <div className="network-upload"><div className="network-upload-icon"><FileCode2 size={22}/></div><h2>Select a binary sample</h2><p>Files are read locally in your browser. No upload, execution or network lookup occurs.</p><label className="network-file"><input type="file" onChange={e=>{setFile(e.target.files?.[0]||null);setDetail(null);setError("");}}/>Choose binary</label>{file&&<div className="network-filename">{file.name} · {(file.size/1024).toFixed(1)} KB</div>}<button className="network-run" onClick={analyse} disabled={!file||busy}>{busy?"Inspecting…":"Inspect headers"}</button><div className="network-limit">MAXIMUM FILE SIZE: 10 MB</div></div>
   {error&&<div className="agent-error"><AlertTriangle size={14}/>{error}</div>}
   {detail&&<section className="network-results"><h2>Format metadata</h2><div className="osint-kv"><span>Format</span><strong>{detail.format}</strong></div><div className="osint-kv"><span>Architecture</span><strong>{detail.architecture}</strong></div><div className="osint-kv"><span>Byte order</span><strong>{detail.endianness}</strong></div><div className="osint-kv"><span>Sections</span><strong>{detail.sections}</strong></div><div className="osint-kv"><span>Timestamp</span><strong>{detail.timestamp}</strong></div><div className="osint-kv"><span>Entry point</span><strong>{detail.entryPoint}</strong></div><div className="osint-kv"><span>Subsystem / ABI</span><strong>{detail.subsystem}</strong></div><p>{detail.note}</p></section>}
   <div className="agent-disclaimer"><ShieldCheck size={12}/> Static format inspection only. This is not a malware verdict, decompiler or debugger. Never execute unknown binaries on your primary workstation.</div>
  </section>
 </main>;
}
