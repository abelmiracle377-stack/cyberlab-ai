"use client";

import { useState } from "react";
import Link from "next/link";
import { ArrowLeft, ShieldCheck, FileKey, Fingerprint, LockKeyhole, AlertTriangle, CheckCircle2, HardDrive, RefreshCw } from "lucide-react";
import { inspectWalletJson, isSecretMaterialFilename } from "../../lib/wallet-backup-inspection";

type Inspection = {
  name: string;
  size: number;
  sha256: string;
  format: string;
  status: "recognized" | "opaque" | "unsupported";
  details: string[];
};

const MAX_FILE_BYTES = 50 * 1024 * 1024;
const MAX_JSON_BYTES = 2 * 1024 * 1024;

function formatSize(bytes: number) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(2) + " MB";
}

function hex(buffer: ArrayBuffer) {
  return Array.from(new Uint8Array(buffer), (value) => value.toString(16).padStart(2, "0")).join("");
}


export default function WalletRecoveryPage() {
  const [inspection, setInspection] = useState<Inspection | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("No backup selected. Nothing is uploaded or stored.");

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
      const digest = hex(await crypto.subtle.digest("SHA-256", bytes));
      let result: ReturnType<typeof inspectWalletJson> = {
        format: "Unclassified backup / binary wallet file",
        status: "opaque",
        details: ["The file was fingerprinted locally only. No binary parser or recovery adapter is enabled for this format."]
      };
      if (lower.endsWith(".json")) {
        let parsed: unknown;
        try { parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
        catch { throw new Error("The selected .json file is not valid UTF-8 JSON."); }
        result = inspectWalletJson(parsed);
      } else if (lower === "wallet.dat" || lower.endsWith(".dat")) {
        result = {
          format: "Bitcoin Core wallet backup (binary candidate)",
          status: "opaque",
          details: ["The filename suggests a Bitcoin Core wallet backup, but its contents were not parsed.", "Use a verified offline Bitcoin Core-compatible recovery environment; do not upload this file."]
        };
      } else if (lower.endsWith(".txt") || lower.endsWith(".seed")) {
        result = {
          format: "Text/seed material — not inspected",
          status: "unsupported",
          details: ["For safety, text and seed files are not read, parsed, displayed or retained by this module.", "Never paste a seed phrase or private key into CyberLab chat or a hosted website."]
        };
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
        <p className="wallet-recovery-intro">A local-first workspace for identifying wallet backup formats and preparing a controlled recovery workflow. The current release performs local file triage and integrity fingerprinting; password recovery and seed derivation adapters are not yet enabled.</p>

        <div className="wallet-security-notice">
          <LockKeyhole size={19}/>
          <div><strong>Secrets stay out of the cloud</strong><p>Selected files are read only in this browser tab. No upload, API request, analytics event, browser storage or server-side logging is used by this page. Do not select a plaintext seed phrase or private-key export.</p></div>
        </div>

        <section className="wallet-panel">
          <div className="wallet-panel-head"><div><span>STEP 01 / BACKUP TRIAGE</span><h2>Inspect a wallet backup</h2></div><FileKey size={20}/></div>
          <label className="wallet-file-drop" htmlFor="wallet-backup-file">
            <HardDrive size={23}/>
            <strong>Select an owned wallet backup</strong>
            <span>JSON keystore, wallet.dat or other backup · maximum 50 MB</span>
            <input id="wallet-backup-file" type="file" onChange={(event) => inspectFile(event.target.files?.[0])} />
          </label>
          <div className="wallet-inline-note"><ShieldCheck size={13}/> Only select a backup you own or are explicitly authorised to recover.</div>
          {busy && <div className="wallet-progress"><RefreshCw size={14}/> Computing SHA-256 and inspecting file structure locally…</div>}
          {error && <div className="wallet-error"><AlertTriangle size={15}/>{error}</div>}
          {inspection && <div className="wallet-inspection">
            <div className="wallet-inspection-head"><div><span>LOCAL INSPECTION RESULT</span><h3>{inspection.format}</h3></div><span className={"wallet-state wallet-state-" + inspection.status}>{inspection.status.toUpperCase()}</span></div>
            <div className="wallet-file-meta"><div><span>FILE</span><b>{inspection.name}</b></div><div><span>SIZE</span><b>{formatSize(inspection.size)}</b></div></div>
            <div className="wallet-hash"><span>SHA-256 FINGERPRINT</span><code>{inspection.sha256}</code></div>
            <ul>{inspection.details.map((detail, index) => <li key={index}>{detail}</li>)}</ul>
            <button type="button" className="wallet-reset" onClick={reset}>Clear inspection</button>
          </div>}
          {!inspection && !error && <p className="wallet-status-line">{notice}</p>}
        </section>

        <section className="wallet-panel wallet-roadmap">
          <div className="wallet-panel-head"><div><span>STEP 02 / RECOVERY ENGINE</span><h2>Adapter availability</h2></div><Fingerprint size={20}/></div>
          <div className="wallet-adapter"><div><b>Ethereum V3 keystore</b><p>Format recognition and metadata checks only</p></div><span className="wallet-state wallet-state-partial">PARTIAL</span></div>
          <div className="wallet-adapter"><div><b>Electrum</b><p>Basic JSON marker recognition only</p></div><span className="wallet-state wallet-state-partial">PARTIAL</span></div>
          <div className="wallet-adapter"><div><b>Bitcoin Core wallet.dat</b><p>Filename identification only; binary parser not installed</p></div><span className="wallet-state wallet-state-planned">PLANNED</span></div>
          <div className="wallet-adapter"><div><b>BIP39 / hardware wallet backups</b><p>No mnemonic validation, derivation or device interaction</p></div><span className="wallet-state wallet-state-planned">PLANNED</span></div>
          <div className="wallet-adapter"><div><b>Offline password recovery workers</b><p>No password candidates, cracking tools or recovery jobs are run by this release</p></div><span className="wallet-state wallet-state-planned">PLANNED</span></div>
        </section>

        <div className="wallet-disclaimer"><AlertTriangle size={16}/><p><strong>Not a recovery result.</strong> A matching file structure or SHA-256 fingerprint does not prove that a wallet is valid, recoverable or belongs to a particular address. Never share recovery material with support, agents or third parties. No wallet connection, signing, transaction or transfer capability exists here.</p></div>
        <div className="wallet-foot"><CheckCircle2 size={13}/> NO FILE UPLOAD · NO SECRET PERSISTENCE · NO TRANSACTIONS</div>
      </section>
    </main>
  );
}
