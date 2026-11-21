"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { CHAIN_REGISTRY, getChainById } from "@/lib/chain-registry";
import { ArrowLeft, ShieldCheck, Code2, Search, AlertTriangle, FileCode2, Sparkles, LoaderCircle } from "lucide-react";

type Model = { id: string; name: string; provider: string; openWeight: boolean };
type EvmProvider = { request: (args: { method: string }) => Promise<unknown>; providers?: EvmProvider[]; isMetaMask?: boolean };
type Eip6963Announcement = { info?: { uuid?: string; name?: string; rdns?: string }; provider?: EvmProvider };

async function discoverEvmProvider(): Promise<{ provider: EvmProvider; name: string } | null> {
  const announced = new Map<string, { provider: EvmProvider; name: string; rdns: string }>();
  const listener = (event: Event) => {
    const detail = (event as CustomEvent<Eip6963Announcement>).detail;
    if (!detail?.provider) return;
    const name = detail.info?.name || "Injected EVM wallet";
    const key = detail.info?.uuid || detail.info?.rdns || name;
    announced.set(key, { provider: detail.provider, name, rdns: detail.info?.rdns || "" });
  };
  window.addEventListener("eip6963:announceProvider", listener);
  window.dispatchEvent(new Event("eip6963:requestProvider"));
  await new Promise(resolve => window.setTimeout(resolve, 250));
  window.removeEventListener("eip6963:announceProvider", listener);
  if (announced.size > 0) {
    const choices = Array.from(announced.values());
    const preferred = choices.find(item => /metamask/i.test(item.rdns + " " + item.name)) || choices[0];
    return { provider: preferred.provider, name: preferred.name };
  }
  const injected = (window as Window & { ethereum?: EvmProvider }).ethereum;
  if (!injected) return null;
  const providers = Array.isArray(injected.providers) ? injected.providers : [];
  const provider = providers.find(item => item.isMetaMask) || providers[0] || injected;
  return { provider, name: provider.isMetaMask ? "MetaMask" : "Injected EVM wallet" };
}
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
  const [walletNetwork, setWalletNetwork] = useState<{chainId:number;name:string;known:boolean}|null>(null);
  const [walletNetworkBusy, setWalletNetworkBusy] = useState(false);
  const [walletNetworkError, setWalletNetworkError] = useState("");
  const [walletProviderName, setWalletProviderName] = useState("");
  const [standard, setStandard] = useState("OpenZeppelin; ERC-20");
  const [projectName, setProjectName] = useState("MyContract");
  const [requirements, setRequirements] = useState("");
  const [generated, setGenerated] = useState("");
  const [generationBusy, setGenerationBusy] = useState(false);
  const [generationError, setGenerationError] = useState("");
  const [compilerStatus, setCompilerStatus] = useState<{available:boolean;version:string|null;message:string}|null>(null);
  const [compilerBusy, setCompilerBusy] = useState(false);
  const [compileResult, setCompileResult] = useState<{status:string;version:string;diagnostics:{severity:string;code:string;message:string;file:string;line:number|null}[];contracts:{name:string;file:string;abi:unknown[];bytecode:string;deploymentSize?:{bytes:number;limit:number;status:string;basis:string;note:string}}[];source_files?:number;dependency_packages?:number;note:string}|null>(null);
  const [compilerError, setCompilerError] = useState("");
  const [projectFilesJson, setProjectFilesJson] = useState(JSON.stringify([
    { path: "src/MyToken.sol", content: 'pragma solidity ^0.8.20; import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol"; contract MyToken is ERC20 { constructor() ERC20("MyToken", "MTK") { _mint(msg.sender, 1_000_000 * 10 ** decimals()); } }' },
    { path: "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol", content: "// Paste the exact ERC20.sol source from your locally verified OpenZeppelin release." },
    { path: "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol", content: "// Paste the exact IERC20.sol source from the same release." },
    { path: "lib/openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Metadata.sol", content: "// Paste the exact IERC20Metadata.sol source from the same release." },
    { path: "lib/openzeppelin-contracts/contracts/utils/Context.sol", content: "// Paste the exact Context.sol source from the same release." }
  ], null, 2));
  const [dependencyLockJson, setDependencyLockJson] = useState("[]");
  const [testRunnerStatus, setTestRunnerStatus] = useState<{available:boolean;message:string;runtime?:string;image?:string}|null>(null);
  const [testFilesJson, setTestFilesJson] = useState(JSON.stringify([
    { path: "src/Vault.sol", content: "pragma solidity ^0.8.20; contract Vault { uint256 public value; function set(uint256 next) external { value = next; } }" },
    { path: "test/Vault.t.sol", content: "pragma solidity ^0.8.20; contract VaultTest { function testPlaceholder() public pure { assert(true); } }" }
  ], null, 2));
  const [testDependencyLockJson, setTestDependencyLockJson] = useState("[]");
  const [testRunnerBusy, setTestRunnerBusy] = useState(false);
  const [testRunnerError, setTestRunnerError] = useState("");
  const [testResult, setTestResult] = useState<{status:string;exit_code:number;result:Record<string,unknown>;sandbox:string;note:string}|null>(null);

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

  async function readWalletNetwork() {
    setWalletNetworkBusy(true);
    setWalletNetworkError("");
    try {
      const detected = await discoverEvmProvider();
      if (!detected) throw new Error("No injected EVM wallet was detected. Open CyberLab inside your wallet's DApp browser (for example, MetaMask Browser) or use a browser with the wallet extension enabled. A normal mobile Chrome tab or an in-app browser may not expose wallet providers.");
      // EIP-1193 eth_chainId is read-only: no account permission, connection prompt, signing or transaction.
      const result = await detected.provider.request({ method: "eth_chainId" });
      setWalletProviderName(detected.name);
      if (typeof result !== "string" || !/^0x[0-9a-fA-F]+$/.test(result)) {
        throw new Error("The wallet returned an invalid chain ID response.");
      }
      const chainId = Number.parseInt(result, 16);
      if (!Number.isSafeInteger(chainId) || chainId <= 0) throw new Error("The wallet returned an unsupported chain ID.");
      const known = getChainById(chainId);
      setWalletNetwork({ chainId, name: known?.name ?? "Unlisted EVM network", known: Boolean(known) });
    } catch (cause) {
      setWalletNetwork(null);
      setWalletProviderName("");
      setWalletNetworkError(cause instanceof Error ? cause.message : "Unable to read wallet network.");
    } finally {
      setWalletNetworkBusy(false);
    }
  }

  function loadBlockchainBlueprint(kind: "erc721" | "erc1155" | "amm") {
    if (kind === "erc721") {
      setLanguage("Solidity"); setCompilerVersion("0.8.24"); setTargetChain("Ethereum-compatible EVM testnet first");
      setStandard("ERC-721 + ERC-2981 (optional advisory royalties)");
      setProjectName("MembershipNFT");
      setRequirements("Create an ERC-721 NFT collection with capped supply, owner-controlled minting, role-separated administration, safe minting, pause/unpause emergency controls, and per-token metadata URI support. Include tests for unauthorized minting, supply cap, safe receiver behavior, transfers, burns if enabled, pause behavior, and role administration. Explain metadata mutability and off-chain hosting assumptions. If ERC-2981 is included, clearly state that royalty information is advisory and marketplace enforcement is not guaranteed. Provide a deployment checklist for a testnet only.");
    } else if (kind === "erc1155") {
      setLanguage("Solidity"); setCompilerVersion("0.8.24"); setTargetChain("Ethereum-compatible EVM testnet first");
      setStandard("ERC-1155 + optional ERC-2981");
      setProjectName("MultiTokenCollection");
      setRequirements("Create an ERC-1155 multi-token collection with distinct token IDs, per-ID supply caps, role-controlled minting, safe batch transfers, pause controls and metadata URI strategy. Include tests for unauthorized minting, per-ID supply boundaries, batch operations, receiver callbacks, pause behavior and role administration. Explain URI mutability and royalty enforcement limitations. Provide testnet-only deployment steps.");
    } else {
      setLanguage("Solidity"); setCompilerVersion("0.8.24"); setTargetChain("Ethereum-compatible EVM testnet first");
      setStandard("Constant-product AMM (educational V2-style)");
      setProjectName("CyberLabAMM");
      setRequirements("Create an educational constant-product AMM with a factory and one pair/pool, liquidity add/remove, swaps, explicit fee accounting, minimum-output and deadline checks, and reserve invariant protection. Include tests for rounding, zero amounts, reserve updates, slippage, deadline expiry, reentrancy surfaces, fee accounting and invariant properties. Discuss oracle manipulation, flash loans, MEV, token compatibility and why this must not hold real funds without independent audit and extensive fuzz/invariant testing. Do not implement a production exchange or claim safety.");
    }
  }

  async function checkLocalCompiler() {
    if (language !== "Solidity") { setCompilerError("The local compiler integration currently supports Solidity only."); return; }
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
    if (language !== "Solidity") { setCompilerError("The local compiler integration currently supports Solidity only."); return; }
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

  async function compileProjectLocally() {
    if (language !== "Solidity") { setCompilerError("The local project compiler currently supports Solidity only."); return; }
    setCompilerBusy(true); setCompilerError(""); setCompileResult(null);
    try {
      const files = JSON.parse(projectFilesJson);
      const dependencyLock = JSON.parse(dependencyLockJson);
      if (!Array.isArray(files) || !Array.isArray(dependencyLock)) throw new Error("Project files and dependency lock must both be JSON arrays.");
      const token = sessionStorage.getItem("cyberlab.kaliBridgeToken");
      if (!token) throw new Error("Pair this browser with the Kali companion first in Kali Connection.");
      const response = await fetch("http://127.0.0.1:8765/solidity/project/compile", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
        body: JSON.stringify({ files, dependencyLock, expectedCompilerVersion: compilerVersion.trim() })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Local project compilation failed.");
      setCompileResult(data);
      setCompilerStatus({ available: true, version: data.version, message: "Local multi-file project compiler completed." });
    } catch (cause) { setCompilerError(cause instanceof Error ? cause.message : "Local project compilation failed."); }
    finally { setCompilerBusy(false); }
  }

  async function checkTestRunner() {
    setTestRunnerBusy(true); setTestRunnerError("");
    try {
      const token = sessionStorage.getItem("cyberlab.kaliBridgeToken");
      if (!token) throw new Error("Pair this browser with the Kali companion first in Kali Connection.");
      const response = await fetch("http://127.0.0.1:8765/solidity/tests/status", { headers: { Authorization: "Bearer " + token }, cache: "no-store" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not check the local test runner.");
      setTestRunnerStatus(data);
    } catch (cause) { setTestRunnerError(cause instanceof Error ? cause.message : "Test runner check failed."); }
    finally { setTestRunnerBusy(false); }
  }

  async function runLocalTests() {
    setTestRunnerBusy(true); setTestRunnerError(""); setTestResult(null);
    try {
      if (language !== "Solidity") throw new Error("The local Foundry runner currently supports Solidity only.");
      const files = JSON.parse(testFilesJson);
      const token = sessionStorage.getItem("cyberlab.kaliBridgeToken");
      if (!token) throw new Error("Pair this browser with the Kali companion first in Kali Connection.");
      const response = await fetch("http://127.0.0.1:8765/solidity/tests/run", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
        body: JSON.stringify({ files, dependencyLock: JSON.parse(testDependencyLockJson) }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Local test execution failed.");
      setTestResult(data);
    } catch (cause) { setTestRunnerError(cause instanceof Error ? cause.message : "Local test execution failed."); }
    finally { setTestRunnerBusy(false); }
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

        <section className="solidity-results" aria-labelledby="wallet-network-title">
          <div className="solidity-result-head">
            <div><div className="agent-overline">READ-ONLY WALLET DISCOVERY</div><h2 id="wallet-network-title">Check wallet network</h2></div>
            <ShieldCheck size={18} />
          </div>
          <p className="agent-disclaimer">Discovers EVM wallets through EIP-6963 announcements and legacy window.ethereum injection, then reads only eth_chainId. It does not request accounts, connect a session, switch networks, sign messages or send transactions. Wallet injection depends on the browser: use a wallet's DApp browser or a desktop browser with its wallet extension enabled.</p>
          <div className="solidity-actions">
            <small>{walletNetwork ? `Chain ID ${walletNetwork.chainId} · ${walletNetwork.name} · ${walletProviderName}` : "No wallet network has been read in this session."}</small>
            <button type="button" onClick={readWalletNetwork} disabled={walletNetworkBusy}><Search size={13}/>{walletNetworkBusy ? "Reading…" : "Read wallet chain ID"}</button>
          </div>
          {walletNetwork && <div className="network-results"><strong>{walletNetwork.known ? "Known registry entry" : "Unlisted network"}</strong><p>Provider-reported chain ID: {walletNetwork.chainId}. {walletNetwork.known ? "Compare this value with the intended deployment network before proceeding." : "Do not assume this network is supported; verify its chain ID and documentation independently."}</p></div>}
          {walletNetworkError && <div className="agent-error"><AlertTriangle size={14}/>{walletNetworkError}</div>}
        </section>

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
              <div><label htmlFor="contract-chain">TARGET CHAIN / VM</label><input id="contract-chain" list="known-chain-options" value={targetChain} onChange={event => setTargetChain(event.target.value)} required maxLength={100} /><datalist id="known-chain-options">{CHAIN_REGISTRY.map(chain => <option key={chain.chainId} value={`${chain.name} (chain ID ${chain.chainId})`} />)}</datalist><small>Curated chain IDs are reference metadata only; confirm the connected wallet network independently. Custom networks remain supported.</small></div>
              <div><label htmlFor="contract-standard">STANDARD / FRAMEWORK</label><input id="contract-standard" value={standard} onChange={event => setStandard(event.target.value)} maxLength={100} placeholder="e.g. ERC-721, OpenZeppelin" /></div>
              <div><label htmlFor="contract-project">PROJECT NAME</label><input id="contract-project" value={projectName} onChange={event => setProjectName(event.target.value)} required maxLength={80} /></div>
            </div>
            <div className="solidity-actions" aria-label="Blockchain project blueprints">
              <small>Start from a scoped blueprint, then edit the requirements before generation.</small>
              <button type="button" onClick={() => loadBlockchainBlueprint("erc721")}>ERC-721 NFT</button>
              <button type="button" onClick={() => loadBlockchainBlueprint("erc1155")}>ERC-1155 NFT</button>
              <button type="button" onClick={() => loadBlockchainBlueprint("amm")}>AMM / DEX</button>
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
          <div className="solidity-result-head"><div><div className="agent-overline">LOCAL TOOLCHAIN / PAIRED COMPANION</div><h2 id="local-compile-title">Compile Solidity on your machine</h2></div><Code2 size={18}/></div>
          <p className="agent-disclaimer">The Solidity source is sent directly from this browser to your paired 127.0.0.1 companion, not to CyberLab's hosted API. This first stage supports one import-free source file. It does not run tests, audit code or deploy contracts.</p>
          <div className="solidity-actions">
            <small>{compilerStatus ? (compilerStatus.available ? "solc " + compilerStatus.version + " detected" : compilerStatus.message) : (language !== "Solidity" ? "Local solc is available for Solidity projects only." : "Check whether a local solc compiler is installed.")}</small>
            <button type="button" onClick={checkLocalCompiler} disabled={compilerBusy || language !== "Solidity"}><Search size={13}/>{compilerBusy ? "Working…" : "Check local solc"}</button>
            <button type="button" onClick={compileLocally} disabled={compilerBusy || language !== "Solidity" || !source.trim()}><Code2 size={13}/>{compilerBusy ? "Compiling…" : "Compile single file"}</button>
          </div>
          <div className="solidity-editor">
            <label htmlFor="solidity-project-files">Multi-file project JSON</label>
            <textarea id="solidity-project-files" value={projectFilesJson} onChange={(event) => setProjectFilesJson(event.target.value)} rows={10} spellCheck={false} />
            <label htmlFor="solidity-dependency-lock">Pinned OpenZeppelin dependency lock JSON</label>
            <textarea id="solidity-dependency-lock" value={dependencyLockJson} onChange={(event) => setDependencyLockJson(event.target.value)} rows={6} spellCheck={false} />
            <small>Local-only compilation. Supply every imported source file and a SHA-256 lock entry for every OpenZeppelin source. Verify the release commit and source independently; hashes only confirm that submitted files match the submitted lock.</small>
            <button type="button" onClick={compileProjectLocally} disabled={compilerBusy || language !== "Solidity"}><Code2 size={13}/>{compilerBusy ? "Compiling…" : "Compile multi-file project"}</button>
          </div>
          {compilerError && <div className="agent-error"><AlertTriangle size={14}/>{compilerError}</div>}
          {compileResult && <div className="solidity-limitations">
            <h3>Compiler result: {compileResult.status.toUpperCase()} · solc {compileResult.version}</h3>
            <p>{compileResult.contracts.length} contract artifact(s) · {compileResult.diagnostics.length} diagnostic(s){compileResult.source_files ? ` · ${compileResult.source_files} source files · ${compileResult.dependency_packages || 0} locked dependencies` : ""}</p>
            {compileResult.diagnostics.map((item,index)=><article className="solidity-finding" key={item.code+"-"+index}><div className="solidity-finding-head"><span>{item.code || "COMPILER"} · {item.file || "Contract.sol"}</span><b>{item.severity.toUpperCase()}</b></div><pre>{item.message}</pre></article>)}
            {compileResult.contracts.map(item=><div key={item.file+"-"+item.name}><strong>{item.name}</strong><p>ABI entries: {item.abi.length} · Bytecode characters: {item.bytecode.length}{item.deploymentSize&&item.deploymentSize.status!=="unknown"?" · Deployed size: "+item.deploymentSize.bytes.toLocaleString()+" / "+item.deploymentSize.limit.toLocaleString()+" B ("+(item.deploymentSize.status==="over_limit"?"OVER EIP-170 LIMIT":"within EIP-170")+")":""}</p>{item.deploymentSize&&item.deploymentSize.status==="over_limit"&&<p className="solidity-warning" style={{marginTop:4}}>{item.deploymentSize.note}</p>}</div>)}
            <p>{compileResult.note}</p>
          </div>}
        </section>

        <section className="solidity-results" aria-labelledby="local-tests-title">
          <div className="solidity-result-head"><div><div className="agent-overline">OFFLINE EXECUTION / ROOTLESS CONTAINER</div><h2 id="local-tests-title">Run Solidity tests locally</h2></div><ShieldCheck size={18}/></div>
          <p className="agent-disclaimer">Tests execute only when rootless Podman and a locally preloaded Foundry image pinned by SHA-256 are configured on your paired machine. No image is downloaded, no network is available inside the container, and there is no host-execution fallback. Review test code before running it.</p>
          <div className="solidity-actions">
            <small>{testRunnerStatus ? testRunnerStatus.message : "Check for the required rootless Podman sandbox."}</small>
            <button type="button" onClick={checkTestRunner} disabled={testRunnerBusy || language !== "Solidity"}><Search size={13}/>{testRunnerBusy ? "Checking…" : "Check test sandbox"}</button>
          </div>
          <label htmlFor="solidity-test-files">PROJECT FILES (JSON ARRAY · src/*.sol AND test/*.t.sol)</label>
          <textarea id="solidity-test-files" value={testFilesJson} onChange={event => setTestFilesJson(event.target.value)} spellCheck={false} autoCapitalize="off" autoCorrect="off" />
          <label htmlFor="solidity-test-dependency-lock">Pinned OpenZeppelin dependency lock JSON</label>
          <textarea id="solidity-test-dependency-lock" value={testDependencyLockJson} onChange={event => setTestDependencyLockJson(event.target.value)} rows={5} spellCheck={false} />
          <div className="solidity-actions"><small>2–100 files, 500 KB combined. Only locally supplied, SHA-256-locked OpenZeppelin Contracts 5.x dependencies are accepted. forge-std and network dependencies remain disabled.</small><button type="button" onClick={runLocalTests} disabled={testRunnerBusy || language !== "Solidity"}><Code2 size={13}/>{testRunnerBusy ? "Running tests…" : "Run in sandbox"}</button></div>
          {testRunnerError && <div className="agent-error"><AlertTriangle size={14}/>{testRunnerError}</div>}
          {testResult && <div className="solidity-limitations"><h3>Test result: {testResult.status.toUpperCase()}</h3><p>{testResult.sandbox}</p><pre style={{whiteSpace:"pre-wrap",overflowWrap:"anywhere"}}>{JSON.stringify(testResult.result,null,2)}</pre><p>{testResult.note}</p></div>}
        </section>

        <div className="solidity-warning"><AlertTriangle size={15} /> Source analysis combines pattern rules with scope-aware per-function access-control and reentrancy checks. Findings are review leads, not proof of exploitability or safety; compile and test on your paired companion for authoritative results.</div>
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
