"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

type Device = {
  device_id: string;
  name: string;
  platform: string;
  status: string;
  permissions: Record<string, boolean>;
};
type Job = {
  job_id: string;
  device_id: string;
  action: string;
  status: string;
  approval_reference: string;
  result: unknown;
  error: string;
  created_at: number;
  finished_at: number | null;
  result_sha256?: string | null;
  evidence_record_hash?: string | null;
};

export default function ExecutionRelayPage() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [evidenceChain, setEvidenceChain] = useState<{ status: string; verified: boolean; record_count: number; final_record_hash: string | null; errors: string[] } | null>(null);
  const [deviceName, setDeviceName] = useState("Kali workstation");
  const [platform, setPlatform] = useState<"kali" | "desktop-browser">("kali");
  const [pairingCode, setPairingCode] = useState("");
  const [selectedDevice, setSelectedDevice] = useState("");
  const [action, setAction] = useState("kali.health");
  const [approvalReference, setApprovalReference] = useState("");
  const [approved, setApproved] = useState(false);
  const [targetUrl, setTargetUrl] = useState("");
  const [toolName, setToolName] = useState("nmap");
  const [toolParameters, setToolParameters] = useState('{"target":"example.com","ports":[80,443]}');
  const [targetConfirmation, setTargetConfirmation] = useState("");
  const [timeoutSeconds, setTimeoutSeconds] = useState(45);
  const [ollamaModel, setOllamaModel] = useState("");
  const [ollamaPrompt, setOllamaPrompt] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  const selected = useMemo(() => devices.find((item) => item.device_id === selectedDevice), [devices, selectedDevice]);

  const refresh = useCallback(async () => {
    const [deviceResponse, jobResponse] = await Promise.all([
      fetch("/api/relay/pairing", { cache: "no-store" }),
      fetch("/api/relay/jobs", { cache: "no-store" }),
    ]);
    const deviceData = await deviceResponse.json();
    const jobData = await jobResponse.json();
    if (deviceResponse.ok) {
      const nextDevices = deviceData.devices || [];
      setDevices(nextDevices);
      if (!selectedDevice && nextDevices.length) setSelectedDevice(nextDevices[0].device_id);
    } else setMessage(deviceData.error || "Could not load paired devices.");
    if (jobResponse.ok) { setJobs(jobData.jobs || []); setEvidenceChain(jobData.evidence_chain || null); }
    else setMessage(jobData.error || "Could not load execution jobs.");
  }, [selectedDevice]);

  useEffect(() => { void refresh(); }, [refresh]);

  useEffect(() => {
    if (selected?.platform === "desktop-browser") setAction("desktop.browser.inspect");
    else if (selected?.platform === "kali" && action === "desktop.browser.inspect") setAction("kali.health");
  }, [selected, action]);

  async function createPairing() {
    setBusy(true); setMessage(""); setPairingCode("");
    try {
      const response = await fetch("/api/relay/pairing", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ deviceName, platform }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not create pairing code.");
      setPairingCode(data.pairing_code);
      setMessage("One-time code created. It expires in 10 minutes.");
    } catch (error) { setMessage(error instanceof Error ? error.message : "Pairing failed."); }
    finally { setBusy(false); }
  }

  async function queueJob() {
    setBusy(true); setMessage("");
    try {
      if (!selected) throw new Error("Pair and select an execution device first.");
      if (!approvalReference.trim()) throw new Error("Enter your authorisation or engagement reference.");
      if (!approved) throw new Error("Confirm that you approve this exact action.");
      let payload: Record<string, unknown> = {};
      if (action === "desktop.browser.inspect") {
        const target = new URL(targetUrl);
        if (target.protocol !== "https:") throw new Error("Browser inspection requires an HTTPS URL.");
        payload = { url: target.href, allowed_origins: [target.origin] };
      } else if (action === "kali.ollama.chat") {
        if (!ollamaModel.trim() || !ollamaPrompt.trim()) throw new Error("Enter an installed local Ollama model tag and a prompt.");
        payload = { model: ollamaModel.trim(), prompt: ollamaPrompt.trim() };
      } else if (action === "kali.tool.run") {
        const parameters = JSON.parse(toolParameters);
        if (!parameters || typeof parameters !== "object" || Array.isArray(parameters)) throw new Error("Tool parameters must be a JSON object.");
        if (!targetConfirmation.trim()) throw new Error("Retype the exact authorised target.");
        payload = {
          tool: toolName, parameters, confirmRun: true,
          authorizationReference: approvalReference.trim(),
          targetConfirmation: targetConfirmation.trim(),
          timeoutSeconds,
        };
      }
      const response = await fetch("/api/relay/jobs", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          deviceId: selected.device_id, action, payload,
          approvalReference: approvalReference.trim(), operatorApproved: true,
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || data.error || "Job could not be queued.");
      setMessage("Job queued: " + data.job_id);
      setApproved(false);
      await refresh();
    } catch (error) { setMessage(error instanceof Error ? error.message : "Could not queue job."); }
    finally { setBusy(false); }
  }

  async function cancelJob(jobId: string) {
    setBusy(true);
    try {
      const response = await fetch("/api/relay/jobs/" + encodeURIComponent(jobId) + "/cancel", { method: "POST" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || data.error || "Could not cancel job.");
      setMessage("Cancellation requested for " + jobId);
      await refresh();
    } catch (error) { setMessage(error instanceof Error ? error.message : "Cancellation failed."); }
    finally { setBusy(false); }
  }

  const actions = selected?.platform === "desktop-browser"
    ? [{ value: "desktop.browser.inspect", label: "Ego Lite — read-only page inspection" }]
    : [
        { value: "kali.health", label: "Kali — connection health" },
        { value: "kali.tools.inventory", label: "Kali — installed tool inventory" },
        { value: "kali.ollama.models", label: "Kali — local Ollama models" },
        { value: "kali.ollama.chat", label: "Kali — run local Ollama/Qwen analysis" },
        { value: "kali.tool.run", label: "Kali — run registered tool" },
      ];

  return (
    <main className="mx-auto max-w-6xl space-y-6 p-4 text-slate-100 md:p-8">
      <header className="space-y-2">
        <p className="text-xs font-semibold uppercase tracking-[0.25em] text-emerald-400">CyberLab AI / Operations</p>
        <h1 className="text-3xl font-semibold">Cross-machine execution relay</h1>
        <p className="max-w-3xl text-sm text-slate-400">Pair your separate Kali workstation and Ego Lite desktop. Jobs travel over outbound HTTPS, require an approval reference, and return execution receipts to CyberLab.</p>
      </header>

      {message && <div role="status" className="rounded-xl border border-slate-700 bg-slate-900 p-3 text-sm">{message}</div>}

      <section className="grid gap-4 md:grid-cols-2">
        <div className="rounded-2xl border border-slate-800 bg-slate-950 p-5 space-y-4">
          <div><h2 className="text-lg font-semibold">Pair an execution device</h2><p className="text-xs text-slate-400">Create a one-time code, then accept it from the device you own.</p></div>
          <label className="block text-sm">Device name<input value={deviceName} onChange={e => setDeviceName(e.target.value)} className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 p-2" /></label>
          <label className="block text-sm">Device type<select value={platform} onChange={e => { setPlatform(e.target.value as "kali" | "desktop-browser"); setDeviceName(e.target.value === "kali" ? "Kali workstation" : "Ego Lite desktop"); }} className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 p-2"><option value="kali">Separate Kali Linux machine</option><option value="desktop-browser">Ego Lite desktop (Windows/macOS)</option></select></label>
          <button disabled={busy || !deviceName.trim()} onClick={createPairing} className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-slate-950 disabled:opacity-50">Generate pairing code</button>
          {pairingCode && <div className="rounded-xl border border-emerald-700 bg-emerald-950/40 p-4"><p className="text-xs text-emerald-300">One-time pairing code — expires in 10 minutes</p><p className="my-2 font-mono text-3xl tracking-[0.2em]">{pairingCode}</p><p className="text-xs text-slate-400">Accept this code on the intended device only. Grant job_execution permission. Never paste the returned device token into chat or Git.</p></div>}
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-950 p-5 space-y-4">
          <div className="flex items-center justify-between"><h2 className="text-lg font-semibold">Paired devices</h2><button onClick={() => void refresh()} className="text-sm text-emerald-400">Refresh</button></div>
          {devices.length === 0 && <p className="text-sm text-slate-500">No paired devices yet.</p>}
          <div className="space-y-2">{devices.map(device => <button key={device.device_id} onClick={() => setSelectedDevice(device.device_id)} className={"w-full rounded-xl border p-3 text-left " + (selectedDevice === device.device_id ? "border-emerald-500 bg-emerald-950/30" : "border-slate-800 bg-slate-900")}><div className="flex items-center justify-between"><span className="font-medium">{device.name}</span><span className="text-xs text-emerald-300">{device.status}</span></div><p className="mt-1 text-xs text-slate-400">{device.platform} · {device.device_id}</p><p className="mt-1 text-xs text-slate-500">Execution permission: {device.permissions?.job_execution ? "granted" : "not granted"}</p></button>)}</div>
        </div>
      </section>

      <section className="rounded-2xl border border-slate-800 bg-slate-950 p-5 space-y-4">
        <div><h2 className="text-lg font-semibold">Queue an approved task</h2><p className="text-xs text-slate-400">Only supported typed actions are accepted. The worker will not run arbitrary shell commands or job-supplied JavaScript.</p></div>
        <div className="grid gap-3 md:grid-cols-2">
          <label className="block text-sm">Execution device<select value={selectedDevice} onChange={e => setSelectedDevice(e.target.value)} className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 p-2">{devices.map(d => <option key={d.device_id} value={d.device_id}>{d.name} ({d.platform})</option>)}</select></label>
          <label className="block text-sm">Task<select value={action} onChange={e => setAction(e.target.value)} className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 p-2">{actions.map(a => <option key={a.value} value={a.value}>{a.label}</option>)}</select></label>
          <label className="block text-sm md:col-span-2">Authorisation / engagement reference<input value={approvalReference} onChange={e => setApprovalReference(e.target.value)} placeholder="Your approved engagement or lab reference" className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 p-2" /></label>
          {action === "desktop.browser.inspect" && <label className="block text-sm md:col-span-2">Authorised HTTPS website URL<input value={targetUrl} onChange={e => setTargetUrl(e.target.value)} placeholder="https://your-authorised-test-domain.example" className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 p-2" /></label>}
          {action === "kali.ollama.chat" && <>
            <label className="block text-sm">Installed Ollama model tag<input value={ollamaModel} onChange={e => setOllamaModel(e.target.value)} placeholder="Copy exact tag from Kali Ollama models" className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 p-2" /></label>
            <label className="block text-sm md:col-span-2">Local model prompt<textarea value={ollamaPrompt} onChange={e => setOllamaPrompt(e.target.value)} rows={5} placeholder="Ask the local model to analyse selected non-secret evidence..." className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 p-2" /></label>
            <p className="text-xs text-slate-500 md:col-span-2">The prompt is sent to Ollama on your Kali machine. Do not include passwords, session cookies, private keys or wallet seed phrases.</p>
          </>}
          {action === "kali.tool.run" && <>
            <label className="block text-sm">Registered Kali tool<input value={toolName} onChange={e => setToolName(e.target.value)} className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 p-2" /></label>
            <label className="block text-sm">Exact target confirmation<input value={targetConfirmation} onChange={e => setTargetConfirmation(e.target.value)} className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 p-2" /></label>
            <label className="block text-sm md:col-span-2">Tool parameters (JSON object)<textarea value={toolParameters} onChange={e => setToolParameters(e.target.value)} rows={4} className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 p-2 font-mono text-xs" /></label>
            <label className="block text-sm">Timeout (seconds)<input type="number" min={1} max={120} value={timeoutSeconds} onChange={e => setTimeoutSeconds(Math.max(1, Math.min(120, Number(e.target.value))))} className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 p-2" /></label>
          </>}
        </div>
        <label className="flex items-start gap-3 rounded-xl border border-amber-900/60 bg-amber-950/20 p-3 text-sm"><input type="checkbox" checked={approved} onChange={e => setApproved(e.target.checked)} className="mt-1" /><span>I confirm that I own this system or have explicit permission for this exact target and approve the selected action. I understand that the result will be returned to CyberLab.</span></label>
        <button disabled={busy || !selected || !approved} onClick={queueJob} className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-slate-950 disabled:opacity-50">Queue execution</button>
      </section>

      <section className="rounded-2xl border border-slate-800 bg-slate-950 p-5 space-y-3">
        <div className="flex items-center justify-between"><h2 className="text-lg font-semibold">Execution receipts</h2><button onClick={() => void refresh()} className="text-sm text-emerald-400">Refresh results</button></div>
        {evidenceChain && <div className="rounded-lg border border-slate-800 bg-slate-900 p-3 text-xs"><div className="flex items-center justify-between"><span>Evidence hash chain</span><span className={evidenceChain.verified ? "text-emerald-300" : "text-amber-300"}>{evidenceChain.status} · {evidenceChain.record_count} records</span></div>{evidenceChain.final_record_hash && <p className="mt-1 break-all font-mono text-slate-500">Head: {evidenceChain.final_record_hash}</p>}{evidenceChain.errors?.map((error, index) => <p key={index} className="mt-1 text-rose-300">{error}</p>)}</div>}
        {jobs.length === 0 && <p className="text-sm text-slate-500">No execution jobs have been queued.</p>}
        {jobs.map(job => <article key={job.job_id} className="rounded-xl border border-slate-800 bg-slate-900 p-3"><div className="flex flex-wrap items-center justify-between gap-2"><div><p className="font-medium">{job.action}</p><p className="text-xs text-slate-500">{job.job_id} · {job.approval_reference}</p></div><span className="rounded-full border border-slate-700 px-3 py-1 text-xs">{job.status}</span></div>{job.error && <p className="mt-2 text-sm text-rose-300">{job.error}</p>}{job.result_sha256 && <p className="mt-2 break-all text-[10px] text-slate-500">Result SHA-256: {job.result_sha256}</p>}{job.evidence_record_hash && <p className="break-all text-[10px] text-slate-500">Evidence record: {job.evidence_record_hash}</p>}{job.result && <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-black/40 p-3 text-xs text-slate-300">{JSON.stringify(job.result, null, 2)}</pre>}{job.status === "queued" && <button onClick={() => void cancelJob(job.job_id)} disabled={busy} className="mt-2 text-xs text-rose-300">Cancel job</button>}</article>)}
      </section>
    </main>
  );
}
