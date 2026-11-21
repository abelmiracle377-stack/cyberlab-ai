"use client";

import { useState } from "react";
import Link from "next/link";
import { ArrowLeft, ShieldCheck, FileKey, Fingerprint, LockKeyhole, AlertTriangle, CheckCircle2, HardDrive, RefreshCw, KeyRound, Hash, Cpu } from "lucide-react";
import { containsSecretMaterialField, inspectWalletJson, isSecretMaterialFilename } from "../../lib/wallet-backup-inspection";

type Inspection = {
  name: string;
  size: number;
  sha256: string;
  format: string;
  status: "recognized" | "opaque" | "unsupported";
  details: string[];
};

type DerivedAccount = { path: string; address: string; coin?: string; wif?: string; privateKey?: string };
type ExtractedHash = { format: string; hashcatMode?: number; hash: string; note: string };
type CrackResult = { status: string; tool?: string; attack?: string; password?: string; note?: string; exitCode?: number };
type WalletToolStatus = { hashcat: { installed: boolean }; john: { installed: boolean } };
type BalanceRow = { address: string; coin?: string; path?: string; status: string; balance?: string; transaction_count?: number; has_activity?: boolean };
type BalanceResult = { results: BalanceRow[]; checked: number; funded_addresses: number; active_addresses: number; note: string };
type SolverResult = { candidates: string[]; candidate_count: number; checked: number; exhausted: boolean; matched_address?: string | null; note: string };

const ACCOUNT_TEMPLATES: { value: string; label: string }[] = [
  { value: "bip44-ethereum", label: "Ethereum (m/44'/60')" },
  { value: "bip44-legacy", label: "Bitcoin legacy (m/44'/0')" },
  { value: "bip49-p2sh-segwit", label: "Bitcoin nested SegWit (m/49'/0')" },
  { value: "bip84-segwit", label: "Bitcoin native SegWit (m/84'/0')" },
  { value: "litecoin-legacy", label: "Litecoin legacy (m/44'/2')" },
  { value: "litecoin-p2sh-segwit", label: "Litecoin nested SegWit (m/49'/2')" },
  { value: "litecoin-segwit", label: "Litecoin native SegWit (m/84'/2')" },
  { value: "dogecoin-legacy", label: "Dogecoin (m/44'/3')" },
  { value: "bitcoincash", label: "Bitcoin Cash (m/44'/145')" },
  { value: "dash", label: "Dash (m/44'/5')" },
  { value: "zcash-transparent", label: "Zcash transparent (m/44'/133')" },
  { value: "bitcoin-gold", label: "Bitcoin Gold (m/44'/156')" },
  { value: "bitcoin-testnet", label: "Bitcoin testnet (m/44'/1')" },
  { value: "tron", label: "TRON (m/44'/195')" },
  { value: "xrp", label: "XRP / Ripple (m/44'/144')" },
];

const MAX_FILE_BYTES = 50 * 1024 * 1024;
const MAX_JSON_BYTES = 2 * 1024 * 1024;
const BRIDGE = "/api/kali";

function formatSize(bytes: number) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(2) + " MB";
}

function hex(buffer: ArrayBuffer) {
  return Array.from(new Uint8Array(buffer), (value) => value.toString(16).padStart(2, "0")).join("");
}

function bridgeToken() {
  return sessionStorage.getItem("cyberlab.kaliBridgeToken") || "";
}

export default function WalletRecoveryPage() {
  const [inspection, setInspection] = useState<Inspection | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("No backup selected. Nothing is uploaded or stored.");

  // Companion-backed recovery state (runs only against the user's own paired bridge).
  const [tools, setTools] = useState<WalletToolStatus | null>(null);
  const [mnemonic, setMnemonic] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [template, setTemplate] = useState("bip44-ethereum");
  const [accounts, setAccounts] = useState<DerivedAccount[] | null>(null);
  const [deriveWarning, setDeriveWarning] = useState("");
  const [electrumAccounts, setElectrumAccounts] = useState<DerivedAccount[] | null>(null);
  const [electrumType, setElectrumType] = useState("");
  const [extractKind, setExtractKind] = useState("keystore");
  const [extracted, setExtracted] = useState<ExtractedHash | null>(null);
  const [wordlist, setWordlist] = useState("");
  const [crackTool, setCrackTool] = useState("hashcat");
  const [attackMode, setAttackMode] = useState("dictionary");
  const [mask, setMask] = useState("");
  const [rulesFile, setRulesFile] = useState("");
  const [crack, setCrack] = useState<CrackResult | null>(null);
  const [ownAuthorised, setOwnAuthorised] = useState(false);
  const [companionBusy, setCompanionBusy] = useState("");
  const [companionError, setCompanionError] = useState("");
  // Balance check (opt-in, read-only) and seed solver.
  const [balances, setBalances] = useState<BalanceResult | null>(null);
  const [autoResult, setAutoResult] = useState<{ detected: string; schemes: string[]; derived_count: number; recoverable?: boolean; note: string; balances?: BalanceResult } | null>(null);
  const [solverMode, setSolverMode] = useState("missing");
  const [solverPhrase, setSolverPhrase] = useState("");
  const [solverWordlist, setSolverWordlist] = useState("");
  const [solverMatch, setSolverMatch] = useState("");
  const [solver, setSolver] = useState<SolverResult | null>(null);
  // BIP38 encrypted private keys ("6P...").
  const [bip38Key, setBip38Key] = useState("");
  const [bip38Pass, setBip38Pass] = useState("");
  const [bip38Wordlist, setBip38Wordlist] = useState("");
  const [bip38Result, setBip38Result] = useState<{ wif?: string; address?: string; compressed?: boolean; status?: string; passphrase?: string; attempts?: number; note?: string } | null>(null);

  async function inspectFile(file?: File) {
    setError("");
    setInspection(null);
    if (!file) return;
    if (file.size === 0) { setError("The selected file is empty."); return; }
    if (file.size > MAX_FILE_BYTES) { setError("File exceeds the 50 MB local inspection limit."); return; }
    const lower = file.name.toLowerCase();
    if (isSecretMaterialFilename(file.name)) {
      setError("This filename may contain plaintext seed, mnemonic, private-key or secret material. It was rejected before reading or fingerprinting. Use an encrypted wallet backup instead.");
      return;
    }
    if (lower.endsWith(".json") && file.size > MAX_JSON_BYTES) {
      setError("JSON inspection is limited to 2 MB. The file was rejected before reading.");
      return;
    }
    setBusy(true);
    try {
      const bytes = await file.arrayBuffer();
      let digest = "";
      let result: ReturnType<typeof inspectWalletJson> = {
        format: "Unclassified backup / binary wallet file",
        status: "unsupported",
        details: ["No trusted parser or recovery adapter is enabled for this file type; no fingerprint was generated."]
      };
      if (lower.endsWith(".json")) {
        let parsed: unknown;
        try { parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
        catch { throw new Error("The selected .json file is not valid UTF-8 JSON."); }
        if (containsSecretMaterialField(parsed)) {
          throw new Error("This JSON contains fields commonly used for plaintext wallet secrets. It was not fingerprinted. Keep the original file offline and use a trusted wallet-specific recovery tool.");
        }
        result = inspectWalletJson(parsed);
        if (/^Ethereum Web3 Secret Storage \(V3\) candidate$/.test(result.format)) {
          digest = hex(await crypto.subtle.digest("SHA-256", bytes));
        } else {
          result.details.push("No fingerprint was generated for this JSON format because it may contain wallet-secret material.");
        }
      } else if (lower === "wallet.dat" || lower.endsWith(".dat")) {
        result = {
          format: "Bitcoin Core wallet backup (binary candidate)",
          status: "opaque",
          details: ["The filename suggests a Bitcoin Core wallet backup. Use the local recovery workbench below to extract its encrypted master-key hash on your own paired machine."]
        };
        digest = hex(await crypto.subtle.digest("SHA-256", bytes));
      }
      setInspection({ name: file.name, size: file.size, sha256: digest, ...result });
      setNotice("Inspection completed in this browser tab. The file bytes are not retained after the operation.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Local inspection failed.");
    } finally {
      setBusy(false);
    }
  }

  function reset() {
    setInspection(null);
    setError("");
    setNotice("Selection cleared. No backup data is persisted.");
    const input = document.getElementById("wallet-backup-file") as HTMLInputElement | null;
    if (input) input.value = "";
  }

  async function bridgePost(pathname: string, body: unknown) {
    const token = bridgeToken();
    if (!token) throw new Error("Pair your local Kali companion first in Kali Connection; recovery runs on your own machine, not the cloud.");
    const response = await fetch(BRIDGE + pathname, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
      body: JSON.stringify(body),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "The companion rejected the request.");
    return data;
  }

  async function checkTools() {
    setCompanionError("");
    try {
      const token = bridgeToken();
      if (!token) throw new Error("Pair your local Kali companion first in Kali Connection.");
      const response = await fetch(BRIDGE + "/wallet/status", { headers: { Authorization: "Bearer " + token } });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not read companion wallet status.");
      setTools(data);
    } catch (cause) {
      setCompanionError(cause instanceof Error ? cause.message : "Companion status check failed.");
    }
  }

  async function deriveAddresses() {
    setCompanionError(""); setAccounts(null); setDeriveWarning("");
    if (!mnemonic.trim()) { setCompanionError("Enter the recovery mnemonic you own."); return; }
    if (!ownAuthorised) { setCompanionError("Confirm you own or are authorised to recover this wallet."); return; }
    setCompanionBusy("derive");
    try {
      const data = await bridgePost("/wallet/derive", { mnemonic: mnemonic.trim(), passphrase, template, count: 5 });
      setAccounts(data.accounts || []);
      if (data.warning) setDeriveWarning(data.warning);
    } catch (cause) {
      setCompanionError(cause instanceof Error ? cause.message : "Derivation failed.");
    } finally {
      setCompanionBusy("");
    }
  }

  async function extractHash(file?: File) {
    setCompanionError(""); setExtracted(null); setCrack(null);
    if (!file) return;
    if (!ownAuthorised) { setCompanionError("Confirm you own or are authorised to recover this wallet."); return; }
    setCompanionBusy("extract");
    try {
      let body: Record<string, unknown>;
      if (extractKind === "metamask") {
        body = { kind: "metamask", vaultJson: new TextDecoder().decode(await file.arrayBuffer()) };
      } else if (extractKind === "wallet.dat") {
        const bytes = new Uint8Array(await file.arrayBuffer());
        let binary = "";
        bytes.forEach((b) => { binary += String.fromCharCode(b); });
        body = { kind: "wallet.dat", walletDatBase64: btoa(binary) };
      } else {
        body = { kind: "keystore", keystoreJson: new TextDecoder().decode(await file.arrayBuffer()) };
      }
      const data = await bridgePost("/wallet/extract-hash", body);
      setExtracted(data);
    } catch (cause) {
      setCompanionError(cause instanceof Error ? cause.message : "Hash extraction failed.");
    } finally {
      setCompanionBusy("");
    }
  }

  async function runRecovery() {
    setCompanionError(""); setCrack(null);
    if (!extracted) { setCompanionError("Extract a wallet hash first."); return; }
    if (!wordlist.trim()) { setCompanionError("Enter the path to a wordlist on your paired machine."); return; }
    if (!ownAuthorised) { setCompanionError("Confirm you own or are authorised to recover this wallet."); return; }
    setCompanionBusy("crack");
    try {
      const body: Record<string, unknown> = { tool: crackTool, hash: extracted.hash, confirmRun: true };
      const needsWordlist = crackTool === "john" || attackMode !== "mask";
      if (needsWordlist) body.wordlist = wordlist.trim();
      if (crackTool === "hashcat") {
        body.hashcatMode = extracted.hashcatMode;
        body.attackMode = attackMode;
        if (attackMode !== "dictionary") body.mask = mask.trim();
        if (attackMode === "dictionary" && rulesFile.trim()) body.rulesFile = rulesFile.trim();
      } else if (rulesFile.trim()) {
        body.rules = rulesFile.trim();
      }
      const data = await bridgePost("/wallet/crack", body);
      setCrack(data);
    } catch (cause) {
      setCompanionError(cause instanceof Error ? cause.message : "Recovery run failed.");
    } finally {
      setCompanionBusy("");
    }
  }

  async function bip38Decrypt() {
    setCompanionError(""); setBip38Result(null);
    if (!bip38Key.trim()) { setCompanionError("Enter the BIP38 key (starts with 6P)."); return; }
    if (!bip38Pass) { setCompanionError("Enter the passphrase."); return; }
    if (!ownAuthorised) { setCompanionError("Confirm you own or are authorised to recover this wallet."); return; }
    setCompanionBusy("bip38d");
    try {
      setBip38Result(await bridgePost("/wallet/bip38-decrypt", { encryptedKey: bip38Key.trim(), passphrase: bip38Pass }));
    } catch (cause) {
      setCompanionError(cause instanceof Error ? cause.message : "BIP38 decryption failed.");
    } finally {
      setCompanionBusy("");
    }
  }

  async function bip38Crack() {
    setCompanionError(""); setBip38Result(null);
    if (!bip38Key.trim()) { setCompanionError("Enter the BIP38 key (starts with 6P)."); return; }
    if (!bip38Wordlist.trim()) { setCompanionError("Enter a passphrase-list path on your machine."); return; }
    if (!ownAuthorised) { setCompanionError("Confirm you own or are authorised to recover this wallet."); return; }
    setCompanionBusy("bip38c");
    try {
      setBip38Result(await bridgePost("/wallet/bip38-crack", { encryptedKey: bip38Key.trim(), wordlistPath: bip38Wordlist.trim() }));
    } catch (cause) {
      setCompanionError(cause instanceof Error ? cause.message : "BIP38 passphrase search failed.");
    } finally {
      setCompanionBusy("");
    }
  }

  async function autoRecover() {
    setCompanionError(""); setAutoResult(null);
    if (!mnemonic.trim()) { setCompanionError("Enter the recovery phrase to auto-detect and recover."); return; }
    if (!ownAuthorised) { setCompanionError("Confirm you own or are authorised to recover this wallet."); return; }
    setCompanionBusy("auto");
    try {
      const data = await bridgePost("/wallet/auto-recover", {
        mnemonic: mnemonic.trim(), passphrase, count: 3, includeChange: true,
        checkBalances: true, confirmNetwork: true,
      });
      setAutoResult(data);
    } catch (cause) {
      setCompanionError(cause instanceof Error ? cause.message : "Auto-recovery failed.");
    } finally {
      setCompanionBusy("");
    }
  }

  async function deriveElectrum() {
    setCompanionError(""); setElectrumAccounts(null); setElectrumType("");
    if (!mnemonic.trim()) { setCompanionError("Enter the Electrum recovery phrase."); return; }
    if (!ownAuthorised) { setCompanionError("Confirm you own or are authorised to recover this wallet."); return; }
    setCompanionBusy("electrum");
    try {
      const data = await bridgePost("/wallet/electrum-derive", { mnemonic: mnemonic.trim(), passphrase, count: 5, includeChange: true });
      setElectrumAccounts(data.accounts || []);
      setElectrumType(data.seedType || "");
    } catch (cause) {
      setCompanionError(cause instanceof Error ? cause.message : "Electrum derivation failed.");
    } finally {
      setCompanionBusy("");
    }
  }

  async function checkBalances() {
    setCompanionError(""); setBalances(null);
    if (!mnemonic.trim()) { setCompanionError("Enter the recovery mnemonic to sweep for funds."); return; }
    if (!ownAuthorised) { setCompanionError("Confirm you own or are authorised to recover this wallet."); return; }
    setCompanionBusy("balances");
    try {
      // Deep sweep: every coin, accounts 0-2 and both the receiving and change chains.
      const data = await bridgePost("/wallet/sweep", {
        mnemonic: mnemonic.trim(), passphrase, confirmNetwork: true, checkBalances: true,
        templates: ["bip44-legacy", "bip49-p2sh-segwit", "bip84-segwit", "bip44-ethereum", "litecoin-legacy", "dogecoin-legacy", "bitcoincash"],
        accountCount: 3, includeChange: true, perPath: 3,
      });
      setBalances(data.balances || null);
      if (!data.balances) setCompanionError("Derived " + data.derived_count + " addresses, but the balance lookup was unavailable.");
    } catch (cause) {
      setCompanionError(cause instanceof Error ? cause.message : "Balance check failed.");
    } finally {
      setCompanionBusy("");
    }
  }

  async function solveSeed() {
    setCompanionError(""); setSolver(null);
    if (!solverPhrase.trim()) { setCompanionError("Enter the known words (use ? or _ for a missing word)."); return; }
    if (!solverWordlist.trim()) { setCompanionError("Enter the path to your BIP-39 english.txt on your machine."); return; }
    if (!ownAuthorised) { setCompanionError("Confirm you own or are authorised to recover this wallet."); return; }
    setCompanionBusy("solve");
    try {
      const body: Record<string, unknown> = {
        mode: solverMode, phrase: solverPhrase.trim(), words: solverPhrase.trim(),
        wordlistPath: solverWordlist.trim(), passphrase,
      };
      if (solverMatch.trim()) body.matchAddress = solverMatch.trim();
      const data = await bridgePost("/wallet/solve-seed", body);
      setSolver(data);
    } catch (cause) {
      setCompanionError(cause instanceof Error ? cause.message : "Seed reconstruction failed.");
    } finally {
      setCompanionBusy("");
    }
  }

  return (
    <main className="wallet-recovery-shell">
      <header className="wallet-recovery-top">
        <Link href="/" className="wallet-recovery-back"><ArrowLeft size={14}/> Dashboard</Link>
        <div className="wallet-recovery-brand"><ShieldCheck size={16}/> CYBERLAB AI <span>/</span> WALLET RECOVERY</div>
        <span className="wallet-local-label"><span/> LOCAL-FIRST</span>
      </header>
      <section className="wallet-recovery-main">
        <div className="wallet-recovery-kicker">CRYPTO ASSET SAFETY / 001</div>
        <h1>Wallet backup recovery</h1>
        <p className="wallet-recovery-intro">Identify wallet backup formats in your browser, then run real recovery on your own paired Kali companion: HD address derivation from a mnemonic, encrypted-hash extraction from Ethereum keystores and Bitcoin Core wallet.dat, and offline password recovery with your own wordlist. Nothing is sent to the CyberLab cloud.</p>
        <Link href="/wallet-recovery-intelligence" className="mb-5 flex items-center justify-between rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-4 text-sm hover:bg-emerald-500/10"><span><strong className="block text-emerald-300">AI Wallet Recovery Intelligence</strong><span className="text-slate-400">Assess a case, identify supported recovery paths and review missing evidence before execution.</span></span><span className="text-emerald-300">Open planner →</span></Link>

        <div className="wallet-security-notice">
          <LockKeyhole size={19}/>
          <div><strong>Secrets stay on machines you control</strong><p>Triage happens in this browser tab. Recovery runs only against your own paired companion on 127.0.0.1 — mnemonics, keys and wallet files go to your local machine, never to the CyberLab server. Only use a wallet you own or are explicitly authorised to recover.</p></div>
        </div>

        <section className="wallet-panel">
          <div className="wallet-panel-head"><div><span>STEP 01 / BACKUP TRIAGE</span><h2>Inspect a wallet backup</h2></div><FileKey size={20}/></div>
          <label className="wallet-file-drop" htmlFor="wallet-backup-file">
            <HardDrive size={23}/>
            <strong>Select an owned wallet backup</strong>
            <span>JSON keystore, wallet.dat or other backup · maximum 50 MB</span>
            <input id="wallet-backup-file" type="file" disabled={busy} onChange={(event) => inspectFile(event.target.files?.[0])} />
          </label>
          <div className="wallet-inline-note"><ShieldCheck size={13}/> Only select a backup you own or are explicitly authorised to recover.</div>
          {busy && <div className="wallet-progress"><RefreshCw size={14}/> Inspecting file structure locally; fingerprinting is limited to approved backup types…</div>}
          {error && <div className="wallet-error"><AlertTriangle size={15}/>{error}</div>}
          {inspection && <div className="wallet-inspection">
            <div className="wallet-inspection-head"><div><span>LOCAL INSPECTION RESULT</span><h3>{inspection.format}</h3></div><span className={"wallet-state wallet-state-" + inspection.status}>{inspection.status.toUpperCase()}</span></div>
            <div className="wallet-file-meta"><div><span>FILE</span><b>{inspection.name}</b></div><div><span>SIZE</span><b>{formatSize(inspection.size)}</b></div></div>
            {inspection.sha256 && <div className="wallet-hash"><span>SHA-256 FINGERPRINT</span><code>{inspection.sha256}</code></div>}
            <ul>{inspection.details.map((detail, index) => <li key={index}>{detail}</li>)}</ul>
            <button type="button" className="wallet-reset" onClick={reset}>Clear inspection</button>
          </div>}
          {!inspection && !error && <p className="wallet-status-line">{notice}</p>}
        </section>

        <section className="wallet-panel">
          <div className="wallet-panel-head"><div><span>STEP 02 / LOCAL RECOVERY WORKBENCH</span><h2>Run on your paired companion</h2></div><Cpu size={20}/></div>
          <div className="wallet-inline-note"><ShieldCheck size={13}/> These actions call your own machine on 127.0.0.1:8765. Pair it in Kali Connection first.</div>
          <div className="scope-checks"><label><input type="checkbox" checked={ownAuthorised} onChange={(e) => setOwnAuthorised(e.target.checked)} /> I own this wallet or have explicit written authorisation to recover it.</label></div>
          <button type="button" className="wallet-reset" onClick={checkTools}>Check companion recovery tools</button>
          {tools && <p className="wallet-status-line">hashcat: {tools.hashcat.installed ? "installed" : "not installed"} · John: {tools.john.installed ? "installed" : "not installed"}</p>}
          {companionError && <div className="wallet-error"><AlertTriangle size={15}/>{companionError}</div>}

          <div className="wallet-inspection">
            <div className="wallet-inspection-head"><div><span>ONE-BUTTON RECOVERY</span><h3>Auto-detect seed type & recover</h3></div><ShieldCheck size={16}/></div>
            <p className="wallet-inline-note">Paste your recovery phrase in the mnemonic box below, then let the companion detect whether it&apos;s BIP39, Electrum v2 (standard/segwit) or Electrum old, derive across accounts and change chains, and report which path holds funds.</p>
            <button type="button" className="wallet-reset" disabled={companionBusy === "auto"} onClick={autoRecover}>{companionBusy === "auto" ? "Detecting & recovering…" : "Auto-detect & recover"}</button>
            {autoResult && <div className="wallet-balance-result">
              <p className="wallet-status-line">Detected: <strong>{autoResult.detected || "—"}</strong>{autoResult.recoverable === false ? " · not recoverable from the seed alone" : " · " + autoResult.derived_count + " addresses derived"}</p>
              {autoResult.balances && <>
                <p className="wallet-status-line">{autoResult.balances.funded_addresses} funded · {autoResult.balances.active_addresses} ever active of {autoResult.balances.checked} checked</p>
                <ul>{autoResult.balances.results.filter((r) => r.has_activity).map((r) => <li key={(r.path || "") + r.address}><code>{r.path}</code> {r.coin} — <strong>{r.balance}</strong></li>)}</ul>
                {autoResult.balances.active_addresses === 0 && <p className="wallet-status-line">No activity found on the derived paths.</p>}
              </>}
              <p className="wallet-inline-note"><ShieldCheck size={13}/> {autoResult.note}</p>
            </div>}
          </div>

          <div className="wallet-inspection">
            <div className="wallet-inspection-head"><div><span>HD DERIVATION</span><h3>Derive addresses from a mnemonic</h3></div><KeyRound size={16}/></div>
            <textarea value={mnemonic} onChange={(e) => setMnemonic(e.target.value)} placeholder="12 / 24-word BIP39 recovery mnemonic you own" rows={2} className="wallet-mnemonic-input" />
            <div className="wallet-file-meta">
              <div><span>PASSPHRASE (OPTIONAL)</span><input value={passphrase} onChange={(e) => setPassphrase(e.target.value)} placeholder="BIP39 passphrase" /></div>
              <div><span>ACCOUNT TYPE</span>
                <select value={template} onChange={(e) => setTemplate(e.target.value)}>
                  {ACCOUNT_TEMPLATES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
                </select>
              </div>
            </div>
            <div className="wallet-btn-row">
              <button type="button" className="wallet-reset" disabled={companionBusy === "derive"} onClick={deriveAddresses}>{companionBusy === "derive" ? "Deriving…" : "Derive first 5 addresses"}</button>
              <button type="button" className="wallet-reset" disabled={companionBusy === "balances"} onClick={checkBalances} title="Opt-in, read-only public-explorer lookup of your derived addresses across coins">{companionBusy === "balances" ? "Checking funds…" : "Find which path holds funds"}</button>
            </div>
            {accounts && <ul>{accounts.map((acc) => <li key={acc.path}><code>{acc.path}</code> → <code>{acc.address}</code>{acc.coin ? " (" + acc.coin + ")" : ""}</li>)}</ul>}
            {deriveWarning && <div className="wallet-error"><AlertTriangle size={15}/>{deriveWarning}</div>}
            {deriveWarning && deriveWarning.includes("electrum-derive") && <button type="button" className="wallet-reset" disabled={companionBusy === "electrum"} onClick={deriveElectrum}>{companionBusy === "electrum" ? "Deriving Electrum…" : "Derive as Electrum wallet"}</button>}
            {electrumAccounts && <div className="wallet-balance-result">
              <p className="wallet-status-line">Electrum {electrumType} wallet · correct addresses</p>
              <ul>{electrumAccounts.map((acc) => <li key={acc.path}><code>{acc.path}</code> → <code>{acc.address}</code></li>)}</ul>
            </div>}
            {balances && <div className="wallet-balance-result">
              <p className="wallet-status-line">{balances.funded_addresses} funded · {balances.active_addresses} ever active of {balances.checked} checked</p>
              <ul>{balances.results.filter((r) => r.has_activity).map((r) => <li key={r.path + r.address}><code>{r.path}</code> {r.coin} — <strong>{r.balance}</strong>{(r.transaction_count ?? 0) > 0 ? " · " + r.transaction_count + " tx" : ""}</li>)}</ul>
              {balances.active_addresses === 0 && <p className="wallet-status-line">No activity found on the checked paths.</p>}
              <p className="wallet-inline-note"><ShieldCheck size={13}/> {balances.note}</p>
            </div>}
          </div>

          <div className="wallet-inspection">
            <div className="wallet-inspection-head"><div><span>SEED RECONSTRUCTION</span><h3>Recover a missing or scrambled phrase</h3></div><KeyRound size={16}/></div>
            <div className="wallet-file-meta">
              <div><span>MODE</span>
                <select value={solverMode} onChange={(e) => setSolverMode(e.target.value)}>
                  <option value="missing">Fill missing words (mark each ? or _)</option>
                  <option value="scramble">Fix word order (known words)</option>
                </select>
              </div>
              <div><span>BIP-39 english.txt PATH</span><input value={solverWordlist} onChange={(e) => setSolverWordlist(e.target.value)} placeholder="/home/you/bip39/english.txt" /></div>
            </div>
            <textarea value={solverPhrase} onChange={(e) => setSolverPhrase(e.target.value)} rows={2} className="wallet-mnemonic-input" placeholder={solverMode === "missing" ? "legal winner thank ? ? ... (all 12/24 positions, ? for each blank)" : "the known words in any order"} />
            <div className="wallet-file-meta"><div><span>KNOWN ADDRESS (OPTIONAL, PINS THE EXACT PHRASE)</span><input value={solverMatch} onChange={(e) => setSolverMatch(e.target.value)} placeholder="a receiving address from this wallet" /></div></div>
            <button type="button" className="wallet-reset" disabled={companionBusy === "solve"} onClick={solveSeed}>{companionBusy === "solve" ? "Searching…" : "Reconstruct phrase"}</button>
            {solver && <div className="wallet-balance-result">
              <p className="wallet-status-line">{solver.candidate_count} checksum-valid candidate{solver.candidate_count === 1 ? "" : "s"} · {solver.checked.toLocaleString()} checked{solver.exhausted ? "" : " · stopped early (narrow the search or add an address)"}</p>
              <ul>{solver.candidates.slice(0, 20).map((c) => <li key={c}><code>{c}</code></li>)}</ul>
              <p className="wallet-inline-note"><ShieldCheck size={13}/> {solver.note}</p>
            </div>}
          </div>

          <div className="wallet-inspection">
            <div className="wallet-inspection-head"><div><span>HASH EXTRACTION</span><h3>Extract a crackable hash</h3></div><Hash size={16}/></div>
            <div className="wallet-file-meta"><div><span>WALLET TYPE</span>
              <select value={extractKind} onChange={(e) => setExtractKind(e.target.value)}>
                <option value="keystore">Ethereum keystore (.json)</option>
                <option value="metamask">MetaMask vault (.json)</option>
                <option value="wallet.dat">Bitcoin Core wallet.dat</option>
              </select>
            </div></div>
            <label className="wallet-file-drop" htmlFor="wallet-extract-file">
              <HardDrive size={20}/>
              <strong>{extractKind === "metamask" ? "Select the MetaMask vault .json" : extractKind === "wallet.dat" ? "Select wallet.dat" : "Select keystore .json"}</strong>
              <span>Extracts the encrypted hash on your machine</span>
              <input id="wallet-extract-file" type="file" disabled={companionBusy === "extract"} onChange={(e) => extractHash(e.target.files?.[0])} />
            </label>
            {extracted && <div className="wallet-hash"><span>{extracted.format}{extracted.hashcatMode ? " · hashcat -m " + extracted.hashcatMode : ""}</span><code>{extracted.hash}</code></div>}
          </div>

          <div className="wallet-inspection">
            <div className="wallet-inspection-head"><div><span>ENCRYPTED PAPER WALLET</span><h3>Decrypt a BIP38 key (6P…)</h3></div><LockKeyhole size={16}/></div>
            <div className="wallet-file-meta"><div><span>BIP38 KEY</span><input value={bip38Key} onChange={(e) => setBip38Key(e.target.value)} placeholder="6Pf... encrypted private key" /></div></div>
            <div className="wallet-file-meta">
              <div><span>PASSPHRASE (IF KNOWN)</span><input type="password" value={bip38Pass} onChange={(e) => setBip38Pass(e.target.value)} placeholder="the passphrase" /></div>
              <div><span>OR PASSPHRASE-LIST PATH</span><input value={bip38Wordlist} onChange={(e) => setBip38Wordlist(e.target.value)} placeholder="/home/you/passphrases.txt" /></div>
            </div>
            <div className="wallet-btn-row">
              <button type="button" className="wallet-reset" disabled={companionBusy === "bip38d"} onClick={bip38Decrypt}>{companionBusy === "bip38d" ? "Decrypting…" : "Decrypt with passphrase"}</button>
              <button type="button" className="wallet-reset" disabled={companionBusy === "bip38c"} onClick={bip38Crack}>{companionBusy === "bip38c" ? "Searching…" : "Try passphrase list"}</button>
            </div>
            {bip38Result && (bip38Result.wif
              ? <div className="wallet-hash"><span>Recovered{bip38Result.compressed ? " (compressed)" : " (uncompressed)"}{bip38Result.passphrase ? " · passphrase: " + bip38Result.passphrase : ""} · {bip38Result.address}</span><code>{bip38Result.wif}</code></div>
              : <div className="wallet-state wallet-state-partial">{(bip38Result.status || "").toUpperCase()}{bip38Result.attempts ? " after " + bip38Result.attempts + " tries" : ""} — {bip38Result.note || ""}</div>)}
          </div>

          <div className="wallet-inspection">
            <div className="wallet-inspection-head"><div><span>PASSWORD RECOVERY</span><h3>Run hashcat / John locally</h3></div><Fingerprint size={16}/></div>
            <div className="wallet-file-meta">
              <div><span>TOOL</span>
                <select value={crackTool} onChange={(e) => setCrackTool(e.target.value)}>
                  <option value="hashcat">hashcat</option>
                  <option value="john">John the Ripper</option>
                </select>
              </div>
              <div><span>ATTACK</span>
                {crackTool === "hashcat" ? (
                  <select value={attackMode} onChange={(e) => setAttackMode(e.target.value)}>
                    <option value="dictionary">Dictionary (+ optional rules)</option>
                    <option value="mask">Mask / brute force</option>
                    <option value="hybrid-wordlist-mask">Hybrid: word + mask</option>
                    <option value="hybrid-mask-wordlist">Hybrid: mask + word</option>
                  </select>
                ) : (
                  <select value={attackMode} onChange={(e) => setAttackMode(e.target.value)}>
                    <option value="dictionary">Wordlist (+ optional rules)</option>
                  </select>
                )}
              </div>
            </div>
            {(crackTool === "john" || attackMode !== "mask") &&
              <div className="wallet-file-meta"><div><span>WORDLIST PATH (ON YOUR MACHINE)</span><input value={wordlist} onChange={(e) => setWordlist(e.target.value)} placeholder="/home/you/wordlists/rockyou.txt" /></div></div>}
            {crackTool === "hashcat" && attackMode !== "dictionary" &&
              <div className="wallet-file-meta"><div><span>MASK (e.g. ?u?l?l?l?l?d?d)</span><input value={mask} onChange={(e) => setMask(e.target.value)} placeholder="?u?l?l?l?l?l?d?d" /></div></div>}
            {attackMode === "dictionary" &&
              <div className="wallet-file-meta"><div><span>{crackTool === "hashcat" ? "RULES FILE (OPTIONAL)" : "JOHN RULES (OPTIONAL, e.g. Jumbo)"}</span><input value={rulesFile} onChange={(e) => setRulesFile(e.target.value)} placeholder={crackTool === "hashcat" ? "/usr/share/hashcat/rules/best64.rule" : "Jumbo"} /></div></div>}
            <button type="button" className="wallet-reset" disabled={companionBusy === "crack" || !extracted} onClick={runRecovery}>{companionBusy === "crack" ? "Recovering…" : "Start password recovery"}</button>
            {crack && <div className={"wallet-state wallet-state-" + (crack.status === "cracked" ? "recognized" : "partial")}>
              {crack.status === "cracked" ? "RECOVERED: " + crack.password : crack.status.toUpperCase() + (crack.attack ? " (" + crack.attack + ")" : "") + " — " + (crack.note || "")}
            </div>}
          </div>
        </section>

        <div className="wallet-disclaimer"><AlertTriangle size={16}/><p><strong>Real tools, honest results.</strong> Password recovery only succeeds if the password is in your wordlist; a result is reported from the tool's own output and never fabricated. A matching format or fingerprint does not prove ownership. Never share recovery material with support, agents or third parties. No wallet connection, signing, transaction or transfer capability exists here.</p></div>
        <div className="wallet-foot"><CheckCircle2 size={13}/> NO CLOUD UPLOAD · LOCAL COMPANION ONLY · NO TRANSACTIONS</div>
      </section>
    </main>
  );
}
