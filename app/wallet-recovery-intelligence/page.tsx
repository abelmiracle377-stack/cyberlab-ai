"use client";

import { useState } from "react";
import Link from "next/link";
import { ArrowLeft, BrainCircuit, ShieldCheck, ClipboardCheck, AlertTriangle, Loader2 } from "lucide-react";

const BRIDGE = "http://127.0.0.1:8765";
const walletTypes = [
  ["bitcoin-core", "Bitcoin Core"],
  ["ethereum-keystore", "Ethereum V3 keystore"],
  ["metamask", "MetaMask"],
  ["bip39", "BIP39 wallet / seed phrase"],
  ["electrum", "Electrum"],
  ["bip38", "BIP38 encrypted key"],
  ["unknown", "Not sure / identify wallet"],
] as const;
const evidenceOptions = [
  ["encryptedBackupAvailable", "I have the encrypted wallet backup"],
  ["partialSeedAvailable", "I have some seed words or fragments"],
  ["completeSeedAvailable", "I have the complete recovery phrase"],
  ["passwordHintsAvailable", "I remember patterns or hints about the password"],
  ["knownPublicAddressAvailable", "I know at least one public wallet address"],
  ["walletVersionKnown", "I know the wallet version"],
  ["backupFormatKnown", "I know the backup file format"],
  ["twoFactorEnabled", "The wallet uses Electrum 2FA / TrustedCoin"],
  ["originalDeviceAvailable", "I still have the original device"],
] as const;

type Assessment = {
  status: string;
  wallet_label: string;
  execution_started: boolean;
  recommended_methods: string[];
  next_steps: string[];
  blockers_and_limits: string[];
  security: string[];
  note: string;
};

export default function WalletRecoveryIntelligencePage() {
  const [walletType, setWalletType] = useState("unknown");
  const [authorizationReference, setAuthorizationReference] = useState("");
  const [ownerConfirmed, setOwnerConfirmed] = useState(false);
  const [evidence, setEvidence] = useState<Record<string, boolean>>({});
  const [assessment, setAssessment] = useState<Assessment | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [mnemonic, setMnemonic] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [confirmRun, setConfirmRun] = useState(false);
  const [checkBalances, setCheckBalances] = useState(false);
  const [confirmNetwork, setConfirmNetwork] = useState(false);
  const [runBusy, setRunBusy] = useState(false);
  const [runResult, setRunResult] = useState<any>(null);

  async function assess() {
    setBusy(true); setError(""); setAssessment(null);
    try {
      const token = sessionStorage.getItem("cyberlab.kaliBridgeToken") || "";
      if (!token) throw new Error("Pair your local Kali companion first in Kali Connection.");
      const response = await fetch(BRIDGE + "/wallet/recovery-assess", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
        body: JSON.stringify({ walletType, ownerConfirmed, authorizationReference, evidence }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The companion rejected the assessment.");
      setAssessment(data);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Assessment failed.");
    } finally {
      setBusy(false);
    }
  }


  async function runRecovery() {
    setRunBusy(true); setError(""); setRunResult(null);
    try {
      const token = sessionStorage.getItem("cyberlab.kaliBridgeToken") || "";
      if (!token) throw new Error("Pair your local Kali companion first in Kali Connection.");
      const response = await fetch(BRIDGE + "/wallet/recovery-run", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
        body: JSON.stringify({ operation: "derive-and-check", ownerConfirmed, authorizationReference, confirmRun, mnemonic, passphrase, count: 5, includeChange: true, checkBalances, confirmNetwork }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The local recovery operation failed.");
      setRunResult(data);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Recovery execution failed.");
    } finally { setRunBusy(false); }
  }
  return (
    <main className="min-h-screen bg-[#0b1118] px-4 py-8 text-slate-100 sm:px-8">
      <div className="mx-auto max-w-5xl space-y-6">
        <Link href="/wallet-recovery" className="inline-flex items-center gap-2 text-sm text-slate-400 hover:text-white"><ArrowLeft size={16}/> Wallet Recovery</Link>
        <header className="space-y-3">
          <div className="flex items-center gap-3"><div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-3"><BrainCircuit className="text-emerald-400" size={25}/></div><div><p className="text-xs uppercase tracking-[0.2em] text-emerald-400">CyberLab Intelligence</p><h1 className="text-3xl font-semibold">Wallet Recovery Case Planner</h1></div></div>
          <p className="max-w-3xl text-sm leading-6 text-slate-400">Describe the evidence you have. The local companion will identify relevant recovery methods, missing information and format limitations before you run a recovery operation.</p>
        </header>

        <section className="grid gap-5 rounded-2xl border border-slate-700 bg-slate-900/70 p-5 md:grid-cols-2">
          <label className="space-y-2 text-sm"><span className="text-slate-300">Wallet type</span><select value={walletType} onChange={e => setWalletType(e.target.value)} className="w-full rounded-lg border border-slate-700 bg-slate-950 p-3">{walletTypes.map(([value,label]) => <option key={value} value={value}>{label}</option>)}</select></label>
          <label className="space-y-2 text-sm"><span className="text-slate-300">Case / authorisation reference</span><input value={authorizationReference} onChange={e => setAuthorizationReference(e.target.value)} maxLength={160} placeholder="e.g. CASE-2026-001" className="w-full rounded-lg border border-slate-700 bg-slate-950 p-3"/></label>
          <div className="space-y-3 md:col-span-2"><h2 className="font-medium">Available evidence</h2><p className="text-xs text-slate-500">Select only what you have. Do not enter seed words, passwords, private keys or upload wallet files here.</p><div className="grid gap-3 sm:grid-cols-2">{evidenceOptions.map(([key,label]) => <label key={key} className="flex items-start gap-3 rounded-lg border border-slate-800 bg-slate-950/70 p-3 text-sm text-slate-300"><input type="checkbox" checked={evidence[key] === true} onChange={e => setEvidence(current => ({...current, [key]: e.target.checked}))} className="mt-1 accent-emerald-500"/>{label}</label>)}</div></div>
          <label className="flex items-start gap-3 text-sm text-slate-300 md:col-span-2"><input type="checkbox" checked={ownerConfirmed} onChange={e => setOwnerConfirmed(e.target.checked)} className="mt-1 accent-emerald-500"/>I confirm that I am the wallet owner or have explicit, verifiable authorisation from the owner.</label>
          <button onClick={assess} disabled={busy} className="inline-flex items-center justify-center gap-2 rounded-lg bg-emerald-600 px-5 py-3 font-medium text-white hover:bg-emerald-500 disabled:opacity-50 md:col-span-2">{busy ? <Loader2 className="animate-spin" size={17}/> : <ClipboardCheck size={17}/>} {busy ? "Assessing case…" : "Assess recovery case"}</button>
        </section>

        <section className="space-y-4 rounded-2xl border border-emerald-500/30 bg-slate-900/80 p-5">
          <div><p className="text-xs uppercase tracking-wider text-emerald-400">Local execution</p><h2 className="text-xl font-semibold">Run real wallet recovery</h2><p className="mt-2 text-sm text-slate-400">This sends the recovery phrase directly to your paired 127.0.0.1 companion, which runs the existing local derivation engine. It is not sent to the hosted CyberLab server.</p></div>
          <label className="block space-y-2 text-sm"><span className="text-slate-300">Recovery phrase (local companion only)</span><textarea value={mnemonic} onChange={e => setMnemonic(e.target.value)} rows={3} autoComplete="off" spellCheck={false} className="w-full rounded-lg border border-slate-700 bg-slate-950 p-3" placeholder="Enter the phrase for a wallet you own"/></label>
          <label className="block space-y-2 text-sm"><span className="text-slate-300">Optional BIP39 / Electrum passphrase</span><input type="password" value={passphrase} onChange={e => setPassphrase(e.target.value)} autoComplete="off" className="w-full rounded-lg border border-slate-700 bg-slate-950 p-3" placeholder="Processed locally only"/></label>
          <label className="flex items-start gap-3 text-sm text-slate-300"><input type="checkbox" checked={checkBalances} onChange={e => {setCheckBalances(e.target.checked); if (!e.target.checked) setConfirmNetwork(false);}} className="mt-1 accent-emerald-500"/>After derivation, perform optional read-only public address balance checks.</label>
          {checkBalances && <label className="flex items-start gap-3 text-sm text-amber-200"><input type="checkbox" checked={confirmNetwork} onChange={e => setConfirmNetwork(e.target.checked)} className="mt-1 accent-amber-500"/>I separately authorise sending derived public addresses to public blockchain explorers. No private keys or seed words are sent.</label>}
          <label className="flex items-start gap-3 text-sm text-amber-200"><input type="checkbox" checked={confirmRun} onChange={e => setConfirmRun(e.target.checked)} className="mt-1 accent-amber-500"/>I have verified ownership / explicit authorisation and approve this local recovery run now.</label>
          <button onClick={runRecovery} disabled={runBusy || !ownerConfirmed || !authorizationReference.trim() || !mnemonic.trim() || !confirmRun || (checkBalances && !confirmNetwork)} className="inline-flex items-center justify-center gap-2 rounded-lg bg-emerald-600 px-5 py-3 font-medium text-white hover:bg-emerald-500 disabled:opacity-40">{runBusy ? <Loader2 className="animate-spin" size={17}/> : <ShieldCheck size={17}/>} {runBusy ? "Running local recovery…" : "Execute recovery locally"}</button>
          {runResult && <div className="space-y-3 rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-4"><p className="font-medium text-emerald-300">Local operation: {runResult.execution}</p><p className="text-sm text-slate-300">Detected: {runResult.result?.detected || "Not identified"} · {runResult.result?.derived_count ?? 0} public addresses derived</p>{runResult.result?.accounts?.length > 0 && <div className="max-h-64 overflow-auto text-xs text-slate-300">{runResult.result.accounts.map((a:any,i:number)=><p key={i} className="break-all py-1"><code>{a.scheme} · {a.path} · {a.address}</code></p>)}</div>}{runResult.result?.balances && <p className="text-sm text-slate-300">Balance check: {runResult.result.balances.funded_addresses} funded · {runResult.result.balances.active_addresses} active · {runResult.result.balances.checked} checked</p>}<p className="text-xs text-slate-500">No signing, transaction or transfer was performed.</p></div>}
        </section>
        {error && <div role="alert" className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">{error}</div>}
        {assessment && <section className="space-y-5 rounded-2xl border border-slate-700 bg-slate-900/70 p-5">
          <div className="flex flex-wrap items-center justify-between gap-3"><div><p className="text-xs uppercase tracking-wider text-slate-500">Assessment result</p><h2 className="text-xl font-semibold">{assessment.wallet_label}</h2></div><span className={"rounded-full px-3 py-1 text-xs "+(assessment.status === "ready_for_operator_review" ? "bg-emerald-500/15 text-emerald-300" : "bg-amber-500/15 text-amber-300")}>{assessment.status.replaceAll("_"," ")}</span></div>
          <div className="grid gap-5 md:grid-cols-2">
            <div><h3 className="mb-2 font-medium">Recommended methods</h3><ul className="list-disc space-y-2 pl-5 text-sm text-slate-300">{assessment.recommended_methods.map((item,i)=><li key={i}>{item}</li>)}</ul></div>
            <div><h3 className="mb-2 font-medium">Next steps</h3><ul className="list-disc space-y-2 pl-5 text-sm text-slate-300">{assessment.next_steps.map((item,i)=><li key={i}>{item}</li>)}</ul></div>
          </div>
          <div><h3 className="mb-2 flex items-center gap-2 font-medium"><AlertTriangle size={16} className="text-amber-400"/> Blockers and limitations</h3><ul className="list-disc space-y-2 pl-5 text-sm text-slate-400">{assessment.blockers_and_limits.map((item,i)=><li key={i}>{item}</li>)}</ul></div>
          <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3"><p className="flex items-center gap-2 text-sm font-medium text-emerald-300"><ShieldCheck size={16}/> Local-first security boundary</p><ul className="mt-2 list-disc space-y-1 pl-5 text-xs text-slate-400">{assessment.security.map((item,i)=><li key={i}>{item}</li>)}</ul></div>
          <p className="text-xs text-slate-500">{assessment.note}</p>
          <p className="text-xs font-medium text-amber-300">No recovery operation was started. Use the existing Wallet Recovery workspace to run a separately confirmed local operation.</p>
        </section>}
      </div>
    </main>
  );
}
