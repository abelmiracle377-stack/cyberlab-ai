"use client";
import { useState } from "react";
import Link from "next/link";
import { ArrowLeft, ShieldCheck, Code2, Search, AlertTriangle, FileCode2 } from "lucide-react";
type Finding={id:string;severity:"critical"|"high"|"medium"|"low"|"info";title:string;description:string;recommendation:string;line:number;evidence:string};
type Analysis={compilerPragmas:string[];contracts:string[];interfaces:string[];libraries:string[];imports:string[];functions:number;findings:Finding[];summary:Record<string,number>;limitations:string[]};
const sample=`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ExampleVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }

    function ownerCheck() external view returns (bool) {
        return tx.origin == msg.sender;
    }
}`;
export default function SolidityLabPage(){
 const [source,setSource]=useState(sample);const [analysis,setAnalysis]=useState<Analysis|null>(null);const [busy,setBusy]=useState(false);const [error,setError]=useState("");
 async function run(event:React.FormEvent){event.preventDefault();setBusy(true);setError("");setAnalysis(null);try{const response=await fetch("/api/solidity/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({source})});const data=await response.json();if(!response.ok)throw new Error(data.error||"Analysis failed.");setAnalysis(data.analysis)}catch(cause){setError(cause instanceof Error?cause.message:"Unexpected analysis error.")}finally{setBusy(false)}}
 return <main className="agent-shell"><header className="agent-topbar"><Link href="/" className="agent-back"><ArrowLeft size={14}/> Dashboard</Link><div className="agent-brand"><Code2 size={16}/> CYBERLAB AI <span className="agent-top-sep">/</span> SOLIDITY LAB</div><span className="agent-secure-label"><span/> LOCAL STATIC RULES</span></header><section className="agent-main"><div className="agent-heading"><div className="agent-overline">BLOCKCHAIN ENGINEERING / 001</div><h1>Solidity source review</h1><p>Inspect Solidity source for selected security-sensitive patterns, map contract surfaces and produce line-referenced review leads.</p></div>
 <div className="solidity-warning"><AlertTriangle size={15}/> Heuristic source analysis only. No compilation, deployment, transaction, wallet connection or chain interaction occurs.</div>
 <form className="solidity-form" onSubmit={run}><div className="solidity-editor-head"><label htmlFor="solidity-source"><FileCode2 size={14}/> Solidity source <span>{source.length.toLocaleString()} / 100,000 characters</span></label><button type="button" onClick={()=>setSource(sample)}>Load example</button></div><textarea id="solidity-source" value={source} onChange={e=>setSource(e.target.value)} maxLength={100000} spellCheck={false} autoCapitalize="off" autoCorrect="off"/><div className="solidity-actions"><small>Paste one or more Solidity source files. Comments and string literals are excluded from rule matching.</small><button disabled={busy||!source.trim()}><Search size={13}/>{busy?"Analysing…":"Analyse source"}</button></div></form>
 {error&&<div className="agent-error"><AlertTriangle size={14}/>{error}</div>}
 {analysis&&<div className="solidity-results"><div className="solidity-result-head"><div><div className="agent-overline">STATIC REVIEW RESULTS</div><h2>Source inventory</h2></div><span>{analysis.findings.length} review leads</span></div>
 <div className="solidity-inventory">{[["CONTRACTS",analysis.contracts.join(", ")||"None detected"],["INTERFACES",analysis.interfaces.join(", ")||"None detected"],["LIBRARIES",analysis.libraries.join(", ")||"None detected"],["COMPILER",analysis.compilerPragmas.join(", ")||"Not declared"],["FUNCTIONS",String(analysis.functions)],["IMPORTS",analysis.imports.join(", ")||"None detected"]].map(([label,value])=><div key={label}><span>{label}</span><b>{value}</b></div>)}</div>
 <div className="solidity-counts">{(["critical","high","medium","low","info"] as const).map(level=><div key={level} className={"solidity-count count-"+level}><span>{level.toUpperCase()}</span><b>{analysis.summary[level]||0}</b></div>)}</div>
 <h2 className="solidity-section-title">Findings and review leads</h2>{analysis.findings.length?analysis.findings.map((item,index)=><article className="solidity-finding" key={item.id+"-"+item.line}><div className="solidity-finding-head"><span>{item.id} · LINE {item.line}</span><b className={"severity-"+item.severity}>{item.severity.toUpperCase()}</b></div><h3>{item.title}</h3><p>{item.description}</p><code>{item.evidence||"Pattern matched"}</code><div><strong>Recommended review:</strong> {item.recommendation}</div></article>):<div className="network-results">No configured rule patterns matched. This is not evidence that the contract is secure.</div>}
 <div className="solidity-limitations"><h3>Analysis limitations</h3><ul>{analysis.limitations.map(item=><li key={item}>{item}</li>)}</ul></div></div>}
 <div className="agent-disclaimer"><ShieldCheck size={12}/> Never provide seed phrases, private keys or production secrets. Review findings with compiler output, tests and specialist audit tools before relying on them.</div>
 </section></main>
}
