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

type DerivedAccount = { path: string; address: string; wif?: string; privateKey?: string };
type ExtractedHash = { format: string; hashcatMode?: number; hash: string; note: string };
type CrackResult = { status: string; tool?: string; password?: string; note?: string; exitCode?: number };
type WalletToolStatus = { hashcat: { installed: boolean }; john: { installed: boolean } };

const MAX_FILE_BYTES = 50 * 1024 * 1024;
const MAX_JSON_BYTES = 2 * 1024 * 1024;
const BRIDGE = "http://127.0.0.1:8765";

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
  const [extracted, setExtracted] = useState<ExtractedHash | null>(null);
  const [wordlist, setWordlist] = useState("");
  const [crackTool, setCrackTool] = useState("hashcat");
  const [crack, setCrack] = useState<CrackResult | null>(null);
  const [ownAuthorised, setOwnAuthorised] = useState(false);
  const [companionBusy, setCompanionBusy] = useState("");
  const [companionError, setCompanionError] = useState("");

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
    setCompanionError(""); setAccounts(null);
    if (!mnemonic.trim()) { setCompanionError("Enter the recovery mnemonic you own."); return; }
    if (!ownAuthorised) { setCompanionError("Confirm you own or are authorised to recover this wallet."); return; }
    setCompanionBusy("derive");
    try {
      const data = await bridgePost("/wallet/derive", { mnemonic: mnemonic.trim(), passphrase, template, count: 5 });
      setAccounts(data.accounts || []);
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
      const lower = file.name.toLowerCase();
      let body: Record<string, unknown>;
      if (lower.endsWith(".json")) {
        body = { kind: "keystore", keystoreJson: new TextDecoder().decode(await file.arrayBuffer()) };
      } else {
        const bytes = new Uint8Array(await file.arrayBuffer());
        let binary = "";
        bytes.forEach((b) => { binary += String.fromCharCode(b); });
        body = { kind: "wallet.dat", walletDatBase64: btoa(binary) };
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
      const body: Record<string, unknown> = { tool: crackTool, hash: extracted.hash, wordlist: wordlist.trim(), confirmRun: true };
      if (crackTool === "hashcat") body.hashcatMode = extracted.hashcatMode;
      const data = await bridgePost("/wallet/crack", body);
      setCrack(data);
    } catch (cause) {
      setCompanionError(cause instanceof Error ? cause.message : "Recovery run failed.");
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
            <div className="wallet-inspection-head"><div><span>HD DERIVATION</span><h3>Derive addresses from a mnemonic</h3></div><KeyRound size={16}/></div>
            <textarea value={mnemonic} onChange={(e) => setMnemonic(e.target.value)} placeholder="12 / 24-word BIP39 recovery mnemonic you own" rows={2} className="wallet-mnemonic-input" />
            <div className="wallet-file-meta">
              <div><span>PASSPHRASE (OPTIONAL)</span><input value={passphrase} onChange={(e) => setPassphrase(e.target.value)} placeholder="BIP39 passphrase" /></div>
              <div><span>ACCOUNT TYPE</span>
                <select value={template} onChange={(e) => setTemplate(e.target.value)}>
                  <option value="bip44-ethereum">Ethereum (m/44'/60')</option>
                  <option value="bip44-legacy">Bitcoin legacy (m/44'/0')</option>
                  <option value="bip84-segwit">Bitcoin native SegWit (m/84'/0')</option>
                </select>
              </div>
            </div>
            <button type="button" className="wallet-reset" disabled={companionBusy === "derive"} onClick={deriveAddresses}>{companionBusy === "derive" ? "Deriving…" : "Derive first 5 addresses"}</button>
            {accounts && <ul>{accounts.map((acc) => <li key={acc.path}><code>{acc.path}</code> → <code>{acc.address}</code></li>)}</ul>}
          </div>

          <div className="wallet-inspection">
            <div className="wallet-inspection-head"><div><span>HASH EXTRACTION</span><h3>Extract a crackable hash</h3></div><Hash size={16}/></div>
            <label className="wallet-file-drop" htmlFor="wallet-extract-file">
              <HardDrive size={20}/>
              <strong>Select keystore .json or wallet.dat</strong>
              <span>Extracts the encrypted hash on your machine</span>
              <input id="wallet-extract-file" type="file" disabled={companionBusy === "extract"} onChange={(e) => extractHash(e.target.files?.[0])} />
            </label>
            {extracted && <div className="wallet-hash"><span>{extracted.format}{extracted.hashcatMode ? " · hashcat -m " + extracted.hashcatMode : ""}</span><code>{extracted.hash}</code></div>}
          </div>

          <div className="wallet-inspection">
            <div className="wallet-inspection-head"><div><span>PASSWORD RECOVERY</span><h3>Run hashcat / John locally</h3></div><Fingerprint size={16}/></div>
            <div className="wallet-file-meta">
              <div><span>WORDLIST PATH (ON YOUR MACHINE)</span><input value={wordlist} onChange={(e) => setWordlist(e.target.value)} placeholder="/home/you/wordlists/rockyou.txt" /></div>
              <div><span>TOOL</span>
                <select value={crackTool} onChange={(e) => setCrackTool(e.target.value)}>
                  <option value="hashcat">hashcat</option>
                  <option value="john">John the Ripper</option>
                </select>
              </div>
            </div>
            <button type="button" className="wallet-reset" disabled={companionBusy === "crack" || !extracted} onClick={runRecovery}>{companionBusy === "crack" ? "Recovering…" : "Start password recovery"}</button>
            {crack && <div className={"wallet-state wallet-state-" + (crack.status === "cracked" ? "recognized" : "partial")}>
              {crack.status === "cracked" ? "RECOVERED: " + crack.password : crack.status.toUpperCase() + " — " + (crack.note || "")}
            </div>}
          </div>
        </section>

        <div className="wallet-disclaimer"><AlertTriangle size={16}/><p><strong>Real tools, honest results.</strong> Password recovery only succeeds if the password is in your wordlist; a result is reported from the tool's own output and never fabricated. A matching format or fingerprint does not prove ownership. Never share recovery material with support, agents or third parties. No wallet connection, signing, transaction or transfer capability exists here.</p></div>
        <div className="wallet-foot"><CheckCircle2 size={13}/> NO CLOUD UPLOAD · LOCAL COMPANION ONLY · NO TRANSACTIONS</div>
      </section>
    </main>
  );
}
