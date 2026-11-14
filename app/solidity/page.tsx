"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, ShieldCheck, Code2, Search, AlertTriangle, FileCode2, Sparkles, LoaderCircle } from "lucide-react";

type Model = { id: string; name: string; provider: string; openWeight: boolean };
type Finding = { id: string; severity: "critical" | "high" | "medium" | "low" | "info"; title: string; description: string; recommendation: string; line: number; evidence: string };
type Analysis = { compilerPragmas: string[]; contracts: string[]; interfaces: string[]; libraries: string[]; imports: string[]; functions: number; findings: Finding[]; summary: Record<string, number>; limitations: string[] };

const sample = `// SPDX-License-Identifier: MIT
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

export default function SolidityLabPage() {
  const [source, setSource] = useState(sample);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [models, setModels] = useState<Model[]>([]);
  const [model, setModel] = useState("");
  const [language, setLanguage] = useState("Solidity");
  const [compilerVersion, setCompilerVersion] = useState("0.8.20");
  const [targetChain, setTargetChain] = useState("EVM-compatible (specify network in requirements)");
  const [standard, setStandard] = useState("OpenZeppelin; ERC-20");
  const [projectName, setProjectName] = useState("MyContract");
  const [requirements, setRequirements] = useState("");
  const [generated, setGenerated] = useState("");
  const [generationBusy, setGenerationBusy] = useState(false);
  const [generationError, setGenerationError] = useState("");
  const [compilerStatus, setCompilerStatus] = useState<{available:boolean;version:string|null;message:string}|null>(null);
  const [compilerBusy, setCompilerBusy] = useState(false);
  const [compileResult, setCompileResult] = useState<{status:string;version:string;diagnostics:{severity:string;code:string;message:string;file:string;line:number|null}[];contracts:{name:string;file:string;abi:unknown[];bytecode:string}[];note:string}|null>(null);
  const [compilerError, setCompilerError] = useState("");

  useEffect(() => {
    let active = true;
    fetch("/api/models").then(async (response) => {
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Model catalogue unavailable.");
      const available = (data.models || []).filter((item: Model) => item.openWeight);
      if (active) {
        setModels(available);
        setModel(available[0]?.id || "");
      }
    }).catch((cause) => {
      if (active) setGenerationError(cause instanceof Error ? cause.message : "Could not load model catalogue.");
    });
    return () => { active = false; };
  }, []);

  async function checkLocalCompiler() {
    setCompilerBusy(true); setCompilerError("");
    try {
      const token = sessionStorage.getItem("cyberlab.kaliBridgeToken");
      if (!token) throw new Error("Pair this browser with the Kali companion first in Kali Connection.");
      const response = await fetch("http://127.0.0.1:8765/solidity/compiler", { headers: { Authorization: "Bearer " + token }, cache: "no-store" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not check the local compiler.");
      setCompilerStatus(data);
    } catch (cause) { setCompilerError(cause instanceof Error ? cause.message : "Local compiler check failed."); }
    finally { setCompilerBusy(false); }
  }

  async function compileLocally() {
    setCompilerBusy(true); setCompilerError(""); setCompileResult(null);
    try {
      const token = sessionStorage.getItem("cyberlab.kaliBridgeToken");
      if (!token) throw new Error("Pair this browser with the Kali companion first in Kali Connection.");
      const response = await fetch("http://127.0.0.1:8765/solidity/compile", { method: "POST", headers: { "Content-Type": "application/json", Authorization: "Bearer " + token }, body: JSON.stringify({ source, expectedCompilerVersion: compilerVersion.trim() }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Local compilation failed.");
      setCompileResult(data);
      setCompilerStatus({ available: true, version: data.version, message: "Local solc compiler completed." });
    } catch (cause) { setCompilerError(cause instanceof Error ? cause.message : "Local compilation failed."); }
    finally { setCompilerBusy(false); }
  }

  async function runAnalysis(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true); setError(""); setAnalysis(null);
    try {
      const response = await fetch("/api/solidity/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ source }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Analysis failed.");
      setAnalysis(data.analysis);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unexpected analysis error.");
    } finally { setBusy(false); }
  }

  async function generateProject(event: React.FormEvent) {
    event.preventDefault();
    if (!model || generationBusy) return;
    setGenerationBusy(true); setGenerationError(""); setGenerated("");
    try {
      const response = await fetch("/api/solidity/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ model: model.startsWith("uncensored:") ? model.slice("uncensored:".length) : model, language, compilerVersion, targetChain, standard, projectName, requirements }),
      });
      if (!response.ok) {
        let message = "Project generation failed.";
        try { const data = await response.json(); message = data.error || message; } catch { /* Keep fallback. */ }
        throw new Error(message);
      }
      setGenerated(await response.text());
    } catch (cause) {
      setGenerationError(cause instanceof Error ? cause.message : "Unexpected generation error.");
    } finally { setGenerationBusy(false); }
  }

  return (
    <main className="agent-shell">
      <header className="agent-topbar">
        <Link href="/" className="agent-back"><ArrowLeft size={14} /> Dashboard</Link>
        <div className="agent-brand"><Code2 size={16} /> CYBERLAB AI <span className="agent-top-sep">/</span> SOLIDITY LAB</div>
        <span className="agent-secure-label"><span /> BLOCKCHAIN ENGINEERING</span>
      </header>
      <section className="agent-main">
        <div className="agent-heading">
          <div className="agent-overline">BLOCKCHAIN ENGINEERING / 001</div>
          <h1>Smart-contract engineering</h1>
          <p>Generate contract projects from instructions and review existing Solidity source. Build, test and deployment integrations are separate validation stages.</p>
        </div>

        <section className="solidity-results" aria-labelledby="contract-generator-title">
          <div className="solidity-result-head">
            <div><div className="agent-overline">AI-ASSISTED PROJECT AUTHORING</div><h2 id="contract-generator-title">Create a smart-contract project</h2></div>
            <Sparkles size={18} />
          </div>
          <p className="agent-disclaimer">Generated code is a draft. This endpoint does not compile, test, audit, deploy or sign transactions. Never include seed phrases, private keys or credentials.</p>
          <form className="solidity-form" onSubmit={generateProject}>
            <div className="solidity-inventory">
              <div><label htmlFor="contract-language">LANGUAGE</label><select id="contract-language" value={language} onChange={event => setLanguage(event.target.value)}><option>Solidity</option><option>Vyper</option><option>Move</option><option>Rust (Anchor)</option></select></div>
              <div><label htmlFor="contract-model">AI MODEL</label><select id="contract-model" value={model} onChange={event => setModel(event.target.value)} disabled={!models.length}><option value="">{models.length ? "Select model" : "No open-weight model available"}</option>{models.map(item => <option key={item.id} value={item.id}>{item.name} · {item.provider}</option>)}</select></div>
              <div><label htmlFor="contract-version">COMPILER / TOOLCHAIN</label><input id="contract-version" value={compilerVersion} onChange={event => setCompilerVersion(event.target.value)} placeholder="e.g. 0.8.20" maxLength={80} /></div>
              <div><label htmlFor="contract-chain">TARGET CHAIN / VM</label><input id="contract-chain" value={targetChain} onChange={event => setTargetChain(event.target.value)} required maxLength={100} /></div>
              <div><label htmlFor="contract-standard">STANDARD / FRAMEWORK</label><input id="contract-standard" value={standard} onChange={event => setStandard(event.target.value)} maxLength={100} placeholder="e.g. ERC-721, OpenZeppelin" /></div>
              <div><label htmlFor="contract-project">PROJECT NAME</label><input id="contract-project" value={projectName} onChange={event => setProjectName(event.target.value)} required maxLength={80} /></div>
            </div>
            <label htmlFor="contract-requirements">NATURAL-LANGUAGE REQUIREMENTS</label>
            <textarea id="contract-requirements" value={requirements} onChange={event => setRequirements(event.target.value)} required maxLength={8000} placeholder="Describe the contract, roles, functions, token economics, events, invariants and expected tests…" />
            <div className="solidity-actions"><small>Up to 8,000 characters. The selected configured open-weight model is used through CyberLab's authenticated gateway.</small><button disabled={generationBusy || !model || !requirements.trim()}><Sparkles size={13} />{generationBusy ? "Generating project…" : "Generate project"}</button></div>
          </form>
          {generationBusy && <div className="agent-thinking"><LoaderCircle size={14} /> Generating source and tests…</div>}
          {generationError && <div className="agent-error"><AlertTriangle size={14} />{generationError}</div>}
          {generated && <div className="solidity-limitations"><h3>AI-generated project draft</h3><pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", fontSize: 13, lineHeight: 1.65 }}>{generated}</pre><p>Not compiled or audited. Next step: validate with a pinned compiler and isolated test runner.</p></div>}
        </section>

        <section className="solidity-results" aria-labelledby="local-compile-title">
          <div className="solidity-result-head"><div><div className="agent-overline">LOCAL TOOLCHAIN / PAIRED COMPANION</div><h2 id="local-compile-title">Compile on your machine</h2></div><Code2 size={18}/></div>
          <p className="agent-disclaimer">The Solidity source is sent directly from this browser to your paired 127.0.0.1 companion, not to CyberLab's hosted API. This first stage supports one import-free source file. It does not run tests, audit code or deploy contracts.</p>
          <div className="solidity-actions">
            <small>{compilerStatus ? (compilerStatus.available ? "solc " + compilerStatus.version + " detected" : compilerStatus.message) : "Check whether a local solc compiler is installed."}</small>
            <button type="button" onClick={checkLocalCompiler} disabled={compilerBusy}><Search size={13}/>{compilerBusy ? "Working…" : "Check local solc"}</button>
            <button type="button" onClick={compileLocally} disabled={compilerBusy || !source.trim()}><Code2 size={13}/>{compilerBusy ? "Compiling…" : "Compile locally"}</button>
          </div>
          {compilerError && <div className="agent-error"><AlertTriangle size={14}/>{compilerError}</div>}
          {compileResult && <div className="solidity-limitations">
            <h3>Compiler result: {compileResult.status.toUpperCase()} · solc {compileResult.version}</h3>
            <p>{compileResult.contracts.length} contract artifact(s) · {compileResult.diagnostics.length} diagnostic(s)</p>
            {compileResult.diagnostics.map((item,index)=><article className="solidity-finding" key={item.code+"-"+index}><div className="solidity-finding-head"><span>{item.code || "COMPILER"} · {item.file || "Contract.sol"}</span><b>{item.severity.toUpperCase()}</b></div><pre>{item.message}</pre></article>)}
            {compileResult.contracts.map(item=><div key={item.file+"-"+item.name}><strong>{item.name}</strong><p>ABI entries: {item.abi.length} · Bytecode characters: {item.bytecode.length}</p></div>)}
            <p>{compileResult.note}</p>
          </div>}
        </section>

        <div className="solidity-warning"><AlertTriangle size={15} /> Heuristic source analysis only. Pattern matches are review leads, not proof of exploitability or safety.</div>
        <form className="solidity-form" onSubmit={runAnalysis}>
          <div className="solidity-editor-head"><label htmlFor="solidity-source"><FileCode2 size={14} /> Solidity source <span>{source.length.toLocaleString()} / 100,000 characters</span></label><button type="button" onClick={() => setSource(sample)}>Load example</button></div>
          <textarea id="solidity-source" value={source} onChange={event => setSource(event.target.value)} maxLength={100000} spellCheck={false} autoCapitalize="off" autoCorrect="off" />
          <div className="solidity-actions"><small>Paste Solidity source. Comments and string literals are excluded from rule matching.</small><button disabled={busy || !source.trim()}><Search size={13} />{busy ? "Analysing…" : "Analyse source"}</button></div>
        </form>
        {error && <div className="agent-error"><AlertTriangle size={14} />{error}</div>}
        {analysis && <div className="solidity-results">
          <div className="solidity-result-head"><div><div className="agent-overline">STATIC REVIEW RESULTS</div><h2>Source inventory</h2></div><span>{analysis.findings.length} review leads</span></div>
          <div className="solidity-inventory">{[["CONTRACTS", analysis.contracts.join(", ") || "None detected"], ["INTERFACES", analysis.interfaces.join(", ") || "None detected"], ["LIBRARIES", analysis.libraries.join(", ") || "None detected"], ["COMPILER", analysis.compilerPragmas.join(", ") || "Not declared"], ["FUNCTIONS", String(analysis.functions)], ["IMPORTS", analysis.imports.join(", ") || "None detected"]].map(([label, value]) => <div key={label}><span>{label}</span><b>{value}</b></div>)}</div>
          <div className="solidity-counts">{(["critical", "high", "medium", "low", "info"] as const).map(level => <div key={level} className={"solidity-count count-" + level}><span>{level.toUpperCase()}</span><b>{analysis.summary[level] || 0}</b></div>)}</div>
          <h2 className="solidity-section-title">Findings and review leads</h2>
          {analysis.findings.length ? analysis.findings.map(item => <article className="solidity-finding" key={item.id + "-" + item.line}><div className="solidity-finding-head"><span>{item.id} · LINE {item.line}</span><b className={"severity-" + item.severity}>{item.severity.toUpperCase()}</b></div><h3>{item.title}</h3><p>{item.description}</p><code>{item.evidence || "Pattern matched"}</code><div><strong>Recommended review:</strong> {item.recommendation}</div></article>) : <div className="network-results">No configured rule patterns matched. This is not evidence that the contract is secure.</div>}
          <div className="solidity-limitations"><h3>Analysis limitations</h3><ul>{analysis.limitations.map(item => <li key={item}>{item}</li>)}</ul></div>
        </div>}
        <div className="agent-disclaimer"><ShieldCheck size={12} /> Generated source and heuristic findings require independent compiler, test and security validation before production use.</div>
      </section>
    </main>
  );
}
