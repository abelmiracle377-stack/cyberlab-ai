"use client";

import { FormEvent, useEffect, useRef, useState } from "react";
import { ArrowLeft, Bot, ChevronDown, CircleAlert, LoaderCircle, Send, ShieldCheck, Sparkles, Paperclip, Mic, Square, FileText, X } from "lucide-react";
import Link from "next/link";

type Model = { id: string; name: string; provider: string; contextLength: number | null; openWeight: boolean; source: "openrouter" | "ollama" };
const modelKey = (item: Model) => `${item.source}::${item.id}`;
type Message = { role: "user" | "assistant"; content: string };
type AgentAttachment = { name: string; mediaType: string; data: string; size: number };
type LocalScanResult = { target: string; duration_seconds: number; method: string; state_summary: { open: number; closed: number; filtered: number }; hosts: { addresses: { address: string }[]; ports: { port: number; state: string; service: string; product: string; version: string }[] }[]; note: string };
type NativeWebFinding = { id?: string; title: string; severity: string; url: string; detail: string; confidence?: string };
type NativeWebCrawlResult = { status: string; scope: { origin: string; authorizationReference: string }; summary: Record<string, number>; pages: Array<{ url: string; status: number | null; contentType?: string; bodyBytes?: number; responseSha256?: string; error?: string; forms?: Array<{ action: string; method: string; fields: Array<{ name: string; type: string }>; submitted: boolean }> }>; findings: NativeWebFinding[]; limitations: string[] };
type NativeWebActiveResult = { status: string; summary: Record<string, number>; checks: Array<{ type: string; url: string; status?: number; parameter?: string; error?: string }>; findings: NativeWebFinding[]; limitations: string[] };
type NativeWebAssessmentResult = { crawl: NativeWebCrawlResult; activeScan?: NativeWebActiveResult; activeScanError?: string };

export default function AgentPage() {
  const [models, setModels] = useState<Model[]>([]);
  const [model, setModel] = useState("");
  const [providerChoice, setProviderChoice] = useState<"openrouter" | "ollama" | "auto">("openrouter");
  const [ollamaConfigured, setOllamaConfigured] = useState(false);
  const [ollamaAvailable, setOllamaAvailable] = useState(false);
  const [agentMode, setAgentMode] = useState<"standard" | "open-weight">("open-weight");
  const [prompt, setPrompt] = useState("");
  const [attachments, setAttachments] = useState<AgentAttachment[]>([]);
  const [audioBusy, setAudioBusy] = useState(false);
  const [recording, setRecording] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const audioChunksRef = useRef<Blob[]>([]);
  const [messages, setMessages] = useState<Message[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [scanRequest, setScanRequest] = useState<{ target: string; ports: string } | null>(null);
  const [scanConfirmation, setScanConfirmation] = useState("");
  const [scanReference, setScanReference] = useState("");
  const [scanAuthorised, setScanAuthorised] = useState(false);
  const [scanBusy, setScanBusy] = useState(false);
  const [scanStatus, setScanStatus] = useState("");
  const [scanResult, setScanResult] = useState<LocalScanResult | null>(null);
  const [webAssessmentRequest, setWebAssessmentRequest] = useState<{ url: string } | null>(null);
  const [webConfirmationUrl, setWebConfirmationUrl] = useState("");
  const [webReference, setWebReference] = useState("");
  const [webAuthorised, setWebAuthorised] = useState(false);
  const [webApproveCrawl, setWebApproveCrawl] = useState(false);
  const [webApproveActive, setWebApproveActive] = useState(false);
  const [webBusy, setWebBusy] = useState(false);
  const [webStatus, setWebStatus] = useState("");
  const [webResult, setWebResult] = useState<NativeWebAssessmentResult | null>(null);

  const endRef = useRef<HTMLDivElement>(null);
  const providerModels = providerChoice === "openrouter" ? models.filter((item) => item.source === "openrouter") : providerChoice === "ollama" ? models.filter((item) => item.source === "ollama") : models;
  const availableModels = agentMode === "open-weight" ? providerModels.filter((item) => item.openWeight) : providerModels;

  useEffect(() => {
    fetch("/api/models")
      .then(async (response) => {
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Model catalogue unavailable.");
        const catalogue: Model[] = data.models || [];
        setModels(catalogue);
        setOllamaConfigured(Boolean(data.providers?.ollamaConfigured));
        setOllamaAvailable(Boolean(data.providers?.ollamaAvailable));
        const eligibleForMode = catalogue.filter((item) => agentMode === "standard" || item.openWeight);
        const preferredSource = eligibleForMode.some((item) => item.source === "openrouter")
          ? "openrouter"
          : eligibleForMode.some((item) => item.source === "ollama") ? "ollama" : "openrouter";
        if (preferredSource === "ollama") setProviderChoice("ollama");
        setModel((current) => {
          const eligible = eligibleForMode.filter((item) => item.source === preferredSource);
          if (eligible.some((item) => modelKey(item) === current)) return current;
          const preferred = eligible.find((item) => item.id === "openai/gpt-5.5") || eligible[0];
          return preferred ? modelKey(preferred) : "";
        });
      })
      .catch((cause) => setError(cause.message || "Could not load model catalogue."));
  }, []);

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages]);

  async function runLocalScan(event: FormEvent) {
    event.preventDefault();
    if (!scanRequest || scanBusy) return;
    const token = sessionStorage.getItem("cyberlab.kaliBridgeToken");
    if (!token) {
      setScanStatus("Kali bridge is not paired in this browser session. Open Kali Connection and pair the local companion first.");
      return;
    }
    const ports: number[] = [];
    for (const part of scanRequest.ports.split(",")) {
      const value = part.trim();
      const range = value.match(/^(\d{1,5})-(\d{1,5})$/);
      if (range) {
        const start = Number(range[1]), end = Number(range[2]);
        if (end < start || end - start > 99) { setScanStatus("Each port range must be ascending and contain at most 100 ports."); return; }
        for (let port = start; port <= end; port++) ports.push(port);
      } else if (/^\d{1,5}$/.test(value)) ports.push(Number(value));
      else { setScanStatus("Enter ports as comma-separated numbers or bounded ranges."); return; }
    }
    const unique = [...new Set(ports)];
    if (!unique.length || unique.length > 100 || unique.some(port => port < 1 || port > 65535)) {
      setScanStatus("Select between 1 and 100 unique TCP ports from 1 to 65535."); return;
    }
    setScanBusy(true); setScanStatus("Submitting approved scan to the paired local Kali bridge…");
    try {
      const response = await fetch("http://127.0.0.1:8765/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
        body: JSON.stringify({
          target: scanRequest.target,
          confirmationTarget: scanConfirmation.trim(),
          authorizationReference: scanReference.trim(),
          authorizationConfirmed: scanAuthorised,
          ports: unique,
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `Local Kali bridge returned HTTP ${response.status}.`);
      setScanResult(data as LocalScanResult);
      setScanStatus("Local Nmap assessment completed. Review the evidence below; this is not a vulnerability verdict.");
      setScanRequest(null);
    } catch (cause) {
      setScanStatus(cause instanceof Error ? cause.message : "Could not reach the local Kali bridge. Confirm that it is running and paired on this same computer.");
    } finally { setScanBusy(false); }
  }

  async function addFiles(fileList: FileList | null) {
    if (!fileList) return;
    const allowed = /^(image\/(png|jpeg|webp|gif)|application\/pdf|text\/(plain|markdown|csv)|application\/(json|xml))$/i;
    let pending = attachments;
    for (const file of Array.from(fileList)) {
      if (file.size > 2 * 1024 * 1024) { setError(file.name + ": maximum file size is 2 MB."); continue; }
      if (!allowed.test(file.type) && !/\.(txt|md|csv|json|xml)$/i.test(file.name)) { setError(file.name + ": supported files are images, PDF, TXT, Markdown, CSV, JSON and XML."); continue; }
      if (pending.length >= 4) { setError("Attach up to four files per message."); break; }
      if (pending.reduce((total, item) => total + item.size, 0) + file.size > 2 * 1024 * 1024) {
        setError("Attachments must total no more than 2 MB per message.");
        continue;
      }
      try {
        const data = await new Promise<string>((resolve, reject) => {
          const reader = new FileReader();
          reader.onload = () => resolve(String(reader.result || ""));
          reader.onerror = () => reject(new Error("Could not read " + file.name + "."));
          reader.readAsDataURL(file);
        });
        pending = [...pending, { name: file.name, mediaType: file.type || "text/plain", data, size: file.size }];
        setAttachments(pending);
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : "Could not read " + file.name + ".");
      }
    }
    if (fileInputRef.current) fileInputRef.current.value = "";
  }

  async function transcribeAudio(file: File, sendDirectly = true) {
    if (file.size > 4 * 1024 * 1024) { setError("Audio files must be 4 MB or smaller."); return; }
    setAudioBusy(true); setError("");
    try {
      const form = new FormData(); const normalizedType = (file.type || "audio/webm").split(";")[0]; const normalizedFile = normalizedType === file.type ? file : new File([file], file.name, { type: normalizedType }); form.append("file", normalizedFile);
      const response = await fetch("/api/agent/transcribe", { method: "POST", body: form });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Audio transcription failed.");
      if (sendDirectly) await sendAgentPrompt(data.text, []);
      else setPrompt(current => [current.trim(), data.text].filter(Boolean).join(current.trim() ? "\n\n" : ""));
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Could not transcribe this audio."); }
    finally { setAudioBusy(false); }
  }

  async function toggleRecording() {
    if (recording) { mediaRecorderRef.current?.stop(); setRecording(false); return; }
    if (!navigator.mediaDevices?.getUserMedia || typeof MediaRecorder === "undefined") { setError("Audio recording is not supported in this browser. Upload an audio file instead."); return; }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const recorder = new MediaRecorder(stream);
      audioChunksRef.current = [];
      recorder.ondataavailable = event => { if (event.data.size) audioChunksRef.current.push(event.data); };
      recorder.onstop = async () => {
        stream.getTracks().forEach(track => track.stop());
        const blob = new Blob(audioChunksRef.current, { type: recorder.mimeType || "audio/webm" });
        const ext = (recorder.mimeType || "").includes("ogg") ? "ogg" : "webm";
        await transcribeAudio(new File([blob], "cyberlab-recording." + ext, { type: blob.type }), true);
      };
      mediaRecorderRef.current = recorder; recorder.start(); setRecording(true);
    } catch { setError("Microphone access was denied or unavailable. You can upload an audio file instead."); }
  }

  async function runLocalWebAssessment(event: FormEvent) {
    event.preventDefault();
    if (!webAssessmentRequest || webBusy) return;
    const token = sessionStorage.getItem("cyberlab.kaliBridgeToken");
    if (!token) { setWebStatus("Pair the local Kali companion first in Kali Connection."); return; }
    setWebBusy(true); setWebStatus("Running the approved native CyberLab web workflow…"); setWebResult(null);
    try {
      const parsed = new URL(webAssessmentRequest.url);
      if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Only HTTP and HTTPS targets are supported.");
      const localHost = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
      const localLabMode = ["localhost", "127.0.0.1", "::1"].includes(localHost);
      const base = {
        confirmationUrl: webConfirmationUrl.trim(),
        authorizationReference: webReference.trim(),
        authorizationConfirmed: webAuthorised,
        localLabMode,
      };
      const crawlResponse = await fetch("http://127.0.0.1:8765/web/crawl", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
        body: JSON.stringify({ ...base, url: webAssessmentRequest.url, confirmRun: webApproveCrawl, maxPages: 10, maxDepth: 2, delayMs: 500 }),
      });
      const crawlData = await crawlResponse.json();
      if (!crawlResponse.ok) throw new Error(crawlData.error || "Native crawler rejected the request.");
      const crawl = crawlData as NativeWebCrawlResult;
      let activeScan: NativeWebActiveResult | undefined;
      let activeScanError: string | undefined;
      if (webApproveActive) {
        const discovered = crawl.pages.filter(page => typeof page.status === "number").map(page => page.url).slice(0, 10);
        const urls = discovered.length ? discovered : [webAssessmentRequest.url];
        try {
          const scanResponse = await fetch("http://127.0.0.1:8765/web/active-scan", {
            method: "POST",
            headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
            body: JSON.stringify({ ...base, urls, confirmRun: true, maxRequests: 10, delayMs: 500 }),
          });
          const scanData = await scanResponse.json();
          if (!scanResponse.ok) throw new Error(scanData.error || "Native active checks were rejected.");
          activeScan = scanData as NativeWebActiveResult;
        } catch (cause) {
          activeScanError = cause instanceof Error ? cause.message : "Native active checks failed.";
        }
      }
      const result: NativeWebAssessmentResult = { crawl, ...(activeScan ? { activeScan } : {}), ...(activeScanError ? { activeScanError } : {}) };
      setWebResult(result);
      setWebAssessmentRequest(null);
      setWebStatus(activeScanError ? "Crawl completed; active checks did not complete. See the error below." : webApproveActive ? "Native crawl and approved active checks completed." : "Native crawl and baseline audit completed.");
      const evidence = {
        scope: crawl.scope,
        crawlSummary: crawl.summary,
        discoveredPages: crawl.pages.map(page => ({ url: page.url, status: page.status, contentType: page.contentType, bodyBytes: page.bodyBytes, responseSha256: page.responseSha256, forms: page.forms, error: page.error })),
        crawlFindings: crawl.findings,
        crawlLimitations: crawl.limitations,
        activeScan: activeScan ? { summary: activeScan.summary, checks: activeScan.checks, findings: activeScan.findings, limitations: activeScan.limitations } : null,
        activeScanError,
      };
      await sendAgentPrompt("Analyse these results returned by CyberLab's native local web assessment engine. Separate confirmed observations from candidate indicators, explain severity and confidence conservatively, and recommend the next safe validation steps. Do not claim checks beyond the evidence below.\n\n" + JSON.stringify(evidence), [], true);
    } catch (cause) {
      setWebStatus(cause instanceof Error ? cause.message : "Native web assessment failed.");
    } finally { setWebBusy(false); }
  }

  async function sendAgentPrompt(text: string, submittedAttachments: AgentAttachment[] = [], skipLocalRouting = false) {
    if ((!text && submittedAttachments.length === 0) || busy) return;
    setError("");
    setScanRequest(null);
    setScanStatus("");
    setScanResult(null);
    if (!skipLocalRouting) { setWebAssessmentRequest(null); setWebStatus(""); setWebResult(null); }
    setPrompt("");
    setAttachments([]);
    const webIntent = /\b(?:scan|crawl|test|assess|audit)\b[\s\S]{0,100}\b(?:https?:\/\/|website|web\s+app|web\s+application)\b|\b(?:website|web\s+app|web\s+application)\b[\s\S]{0,100}\b(?:scan|crawl|test|assess|audit)\b/i.test(text);
    const webTargetMatch = text.match(/https?:\/\/[^\s<>"']+|(?<![@\w-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::\d{1,5})?(?:\/[^\s<>"']*)?/i);
    if (!skipLocalRouting && webIntent && webTargetMatch && submittedAttachments.length === 0) {
      const rawTarget = webTargetMatch[0].replace(/[),.;]+$/, "");
      const targetUrl = /^https?:\/\//i.test(rawTarget) ? rawTarget : "https://" + rawTarget;
      try {
        const parsedTarget = new URL(targetUrl);
        if (!["http:", "https:"].includes(parsedTarget.protocol)) throw new Error("Unsupported target protocol.");
        setMessages((current) => [...current, { role: "user", content: text }, { role: "assistant", content: "I can run CyberLab's native crawler and baseline audit, then optional bounded active checks against this exact origin. Nothing has been sent yet. Pair the local companion and approve each stage below." }]);
        setWebAssessmentRequest({ url: targetUrl });
        setWebConfirmationUrl(parsedTarget.origin);
        setWebReference("");
        setWebAuthorised(false);
        setWebApproveCrawl(false);
        setWebApproveActive(false);
        setWebStatus("");
        setBusy(false);
        return;
      } catch {
        // Leave malformed or unsupported target text to the research agent for clarification.
      }
    }
    const scanMatch = text.match(/\b(?:nmap|scan|port\s+scan|scan\s+ports)\b[\s\S]*?\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}|(?:\d{1,3}\.){3}\d{1,3})\b/i);
    if (scanMatch && submittedAttachments.length === 0) {
      const portsMatch = text.match(/\bports?\s+([0-9,-]+(?:\s*[-,]\s*[0-9]+)*)/i);
      setMessages((current) => [...current, { role: "user", content: text }, { role: "assistant", content: "I can prepare a bounded Nmap TCP scan on your paired local Kali machine. Before anything runs, confirm the exact target, authorisation reference and scope below. No scan has started." }]);
      setScanRequest({ target: scanMatch[1], ports: portsMatch?.[1]?.replace(/\s+/g, "") || "1-100" });
      setBusy(false);
      return;
    }
    setMessages((current) => [...current, { role: "user", content: text || ("Please analyse the attached file(s): " + submittedAttachments.map(file => file.name).join(", ")) }, { role: "assistant", content: "" }]);
    setBusy(true);
    try {
      const response = await fetch("/api/agent", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt: text || "Please inspect the attached material and summarise its security-relevant contents.", attachments: submittedAttachments, model: models.find((item) => modelKey(item) === model)?.id || "", modelSource: models.find((item) => modelKey(item) === model)?.source || "openrouter", fallbackModel: models.find((item) => item.source === "openrouter" && (agentMode === "open-weight" ? item.openWeight : (item.id === "openai/gpt-5.5" || item.openWeight)))?.id || (agentMode === "open-weight" ? "" : "openai/gpt-5.5"), provider: providerChoice, agentMode, history: messages.filter((item) => item.content.trim()).slice(-12), learningContext: (() => { try { const items = JSON.parse(localStorage.getItem("cyberlab.learning.v1") || "[]"); return Array.isArray(items) ? items.filter((item: any) => item?.status === "approved" && typeof item.content === "string").slice(0, 30).map((item: any) => ({ title: String(item.title || "Untitled").slice(0, 160), category: String(item.category || "Other").slice(0, 80), source: String(item.source || "User supplied").slice(0, 120), content: item.content.slice(0, 3000) })) : []; } catch { return []; } })() }),
      });
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || "Agent request failed.");
      }
      if (!response.body) throw new Error("Streaming response was not available.");
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let output = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        output += decoder.decode(value, { stream: true });
        setMessages((current) => {
          const next = [...current];
          next[next.length - 1] = { role: "assistant", content: output };
          return next;
        });
      }
      output += decoder.decode();
      setMessages((current) => {
        const next = [...current];
        next[next.length - 1] = { role: "assistant", content: output || "The model returned an empty response." };
        return next;
      });
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : "Unexpected agent error.";
      setError(message);
      setMessages((current) => current[current.length - 1]?.content ? current : current.slice(0, -1));
    } finally {
      setBusy(false);
    }
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    const text = prompt.trim();
    const submittedAttachments = attachments;
    if ((!text && submittedAttachments.length === 0) || busy || audioBusy) return;
    await sendAgentPrompt(text, submittedAttachments);
  }

  return (
    <main className="agent-shell">
      <header className="agent-topbar">
        <Link href="/" className="agent-back"><ArrowLeft size={14} /> Dashboard</Link>
        <div className="agent-brand"><span className="agent-brand-icon"><ShieldCheck size={16} /></span> CYBERLAB AI <span className="agent-top-sep">/</span> AGENT CONSOLE</div>
        <Link href="/learning" className="agent-secure-label">LEARNING CENTRE ↗</Link>
      </header>
      <section className="agent-main">
        <div className="agent-heading">
          <div className="agent-overline">RESEARCH ORCHESTRATION / 001</div>
          <h1>AI research agent</h1>
          <p>Research security questions, inspect network intelligence, analyse DNS evidence, and look up public CVE records. Open-weight research mode is selected by default.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2 rounded-xl border border-slate-800 bg-[#0b1715] p-3">
          <span className="mr-2 text-[10px] tracking-wider text-slate-500">NATIVE WEB WORKFLOWS</span>
          <Link href="/web-crawler" className="rounded border border-emerald-900/70 px-3 py-2 text-xs text-emerald-300 hover:bg-emerald-950/30">Web discovery & baseline audit</Link>
          <Link href="/web-scanner" className="rounded border border-amber-900/70 px-3 py-2 text-xs text-amber-200 hover:bg-amber-950/30">Safe active checks</Link>
          <span className="text-[10px] text-slate-500">Local companion execution · separate approval required</span>
        </div>
        <div className="agent-config agent-config-stack">
          <div className="agent-mode-switch" role="group" aria-label="Agent mode">
            <button type="button" className={agentMode === "standard" ? "selected" : ""} onClick={() => { setAgentMode("standard"); const choices = providerChoice === "ollama" ? models.filter((item) => item.source === "ollama") : providerChoice === "openrouter" ? models.filter((item) => item.source === "openrouter") : models; if (!choices.some((item) => modelKey(item) === model)) { const preferred = choices.find((item) => item.id === "openai/gpt-5.5") || choices[0]; setModel(preferred ? modelKey(preferred) : ""); } }} disabled={busy}>Standard</button>
            <button type="button" className={agentMode === "open-weight" ? "selected" : ""} onClick={() => { const first = models.find((item) => item.openWeight && (providerChoice === "auto" || (providerChoice === "ollama" ? item.source === "ollama" : item.source === "openrouter"))); setAgentMode("open-weight"); if (first) setModel(modelKey(first)); }} disabled={busy}>Open-weight research mode</button>
          </div>
          <div className="agent-model-label"><span className="agent-live-dot" /> {agentMode === "open-weight" ? "OPEN-WEIGHT MODEL ROUTING" : "MODEL ROUTING"}</div>
          <label className="agent-select-wrap">
            <span className="sr-only">Select provider</span>
            <select value={providerChoice} onChange={(event) => {
              const next = event.target.value as "openrouter" | "ollama" | "auto";
              setProviderChoice(next);
              const choices = next === "openrouter" ? models.filter((item) => item.source === "openrouter") : next === "ollama" ? models.filter((item) => item.source === "ollama") : models;
              const filtered = agentMode === "open-weight" ? choices.filter((item) => item.openWeight) : choices;
              if (!filtered.some((item) => modelKey(item) === model)) setModel(filtered[0] ? modelKey(filtered[0]) : "");
            }} disabled={busy}>
              <option value="openrouter">OpenRouter · Cloud</option>
              <option value="ollama" disabled={!ollamaConfigured}>Ollama · {ollamaConfigured ? (ollamaAvailable ? "Endpoint configured · models detected" : "Endpoint configured · no models detected") : "Not configured"}</option>
              <option value="auto">Automatic · Use selected provider, local first when selected</option>
            </select>
            <ChevronDown size={13} />
          </label>
          <label className="agent-select-wrap">
            <span className="sr-only">Select model</span>
            <select value={model} onChange={(event) => setModel(event.target.value)} disabled={busy}>
              {availableModels.length ? availableModels.map((item) => <option value={modelKey(item)} key={modelKey(item)}>{item.name} · {item.provider} · {item.source === "ollama" ? "LOCAL" : "CLOUD"}</option>) : <option value="">{providerChoice === "ollama" ? "No Ollama models discovered" : agentMode === "open-weight" ? "No recognised open-weight models available" : "No models available"}</option>}
            </select>
            <ChevronDown size={13} />
          </label>
          <span className="agent-model-count">{availableModels.length} MODELS · {providerChoice === "auto" ? "AUTOMATIC ROUTING" : providerChoice.toUpperCase()}</span>
          {providerChoice === "ollama" && <p className="agent-provider-note">{!ollamaConfigured ? "Ollama is not configured on the server. Set OLLAMA_BASE_URL to a secured, network-reachable Ollama endpoint." : !ollamaAvailable ? "The configured endpoint did not return any installed models. Check that Ollama is running and reachable, pull a model with ollama pull <model>, then refresh this page. For Vercel hosting, your computer’s 127.0.0.1 is not reachable from the server." : "Ollama models were discovered. The endpoint must remain reachable by the CyberLab server during inference; your computer’s 127.0.0.1 is not reachable from Vercel."}</p>}
          <span className="agent-model-count">{agentMode === "open-weight" ? `${availableModels.length} OPEN-WEIGHT MODELS` : `${availableModels.length} MODELS AVAILABLE`}</span>
        </div>
        <div className="agent-chat">
          {messages.length === 0 ? (
            <div className="agent-welcome">
              <div className="agent-welcome-icon"><Bot size={25} /></div>
              <h2>What are we investigating?</h2>
              <p>The agent can research public sources, analyse passive IP/DNS intelligence and NVD CVEs. Ask “scan example.com” to prepare a local Kali Nmap scan; it will wait for your explicit scope approval.</p>
              <div className="agent-prompts">
                {["Explain what information an IP address can reveal, and its limits.", "Look up public IP intelligence for an IP address I provide.", "Analyse DNS records for example.com", "Find NVD details for CVE-2024-3094", "Help me plan a safe, authorised assessment of my own web application."].map((item) => <button key={item} onClick={() => setPrompt(item)}>{item}<span>↗</span></button>)}
              </div>
            </div>
          ) : (
            <div className="agent-messages">
              {messages.map((message, index) => <div className={`agent-message ${message.role}`} key={index}>
                <div className="agent-message-avatar">{message.role === "assistant" ? <Bot size={15} /> : "YOU"}</div>
                <div className="agent-message-body"><div className="agent-message-role">{message.role === "assistant" ? "CYBERLAB AGENT" : "YOU"}</div><div className="agent-message-content">{message.content || (busy ? <span className="agent-thinking"><LoaderCircle size={13} /> Thinking and checking available tools…</span> : "")}</div></div>
              </div>)}
              <div ref={endRef} />
            </div>
          )}
        </div>
        {webAssessmentRequest && <section className="kali-panel" style={{ marginTop: 16 }}>
          <h2>Approve native web assessment</h2>
          <p>Target URL: <strong>{webAssessmentRequest.url}</strong>. CyberLab will run its own same-origin GET-only crawler and baseline review. You can separately approve up to 10 non-mutating active checks against discovered pages. No Burp Suite dependency is involved.</p>
          <form className="report-editor" onSubmit={runLocalWebAssessment}>
            <label>Retype exact origin (scheme, hostname and port)<input value={webConfirmationUrl} onChange={event => setWebConfirmationUrl(event.target.value)} placeholder="https://your-authorised-domain.example" required /></label>
            <label>Written authorisation / engagement reference<input value={webReference} onChange={event => setWebReference(event.target.value)} placeholder="LAB-2026-001" required maxLength={160} /></label>
            <div className="scope-checks"><label><input type="checkbox" checked={webAuthorised} onChange={event => setWebAuthorised(event.target.checked)} /> I own this target or have written permission to assess this exact origin.</label></div>
            <div className="scope-checks"><label><input type="checkbox" checked={webApproveCrawl} onChange={event => setWebApproveCrawl(event.target.checked)} /> I approve a same-origin GET-only crawl of up to 10 pages, depth 2, with a 500 ms delay.</label></div>
            <div className="scope-checks"><label><input type="checkbox" checked={webApproveActive} onChange={event => setWebApproveActive(event.target.checked)} /> I separately approve up to 10 bounded OPTIONS/GET active checks on discovered pages.</label></div>
            <button className="report-download" type="submit" disabled={webBusy || !webAuthorised || !webApproveCrawl || !webReference.trim() || !webConfirmationUrl.trim()}>{webBusy ? "Running native assessment…" : "Confirm and run CyberLab web assessment"}</button>
            <button className="report-download" type="button" onClick={() => setWebAssessmentRequest(null)} disabled={webBusy}>Cancel</button>
          </form>
          {webStatus && <p role="status">{webStatus}</p>}
        </section>}
        {webResult && <section className="network-results" style={{ marginTop: 16 }}>
          <h2>Native CyberLab web assessment · {webResult.crawl.scope.origin}</h2>
          <p>Crawl: {webResult.crawl.summary.pagesVisited ?? 0} pages · {webResult.crawl.summary.findings ?? 0} baseline findings · {webResult.activeScan ? String(webResult.activeScan.summary.requestsSent ?? 0) + " active requests" : "active checks not run"}</p>
          {webResult.activeScanError && <p className="agent-error">{webResult.activeScanError}</p>}
          {[...webResult.crawl.findings, ...(webResult.activeScan?.findings || [])].map((finding,index)=><div key={(finding.id || finding.title) + index} className="border-b border-slate-800 py-3">
            <strong>{finding.severity.toUpperCase()} · {finding.title}</strong><p className="mt-1 break-all text-xs text-slate-400">{finding.url}</p><p className="mt-1 text-xs text-slate-400">{finding.detail}</p>
          </div>)}
          <p className="mt-3 text-xs text-slate-500">The AI analysis above uses the returned crawl and active-check evidence. Findings remain candidates until manually verified; this workflow is not yet a full SQLi/SSRF/IDOR/authenticated scanner.</p>
        </section>}
        {scanRequest && <section className="kali-panel" style={{ marginTop: 16 }}>
          <h2>Approve local Nmap scan</h2>
          <p>Target detected from your message: <strong>{scanRequest.target}</strong>. Proposed TCP ports: <strong>{scanRequest.ports}</strong> (maximum 100). The request will run directly in your browser against the paired Kali bridge; it is not sent to the CyberLab server.</p>
          <form className="report-editor" onSubmit={runLocalScan}>
            <label>Retype exact target<input value={scanConfirmation} onChange={event => setScanConfirmation(event.target.value)} placeholder={scanRequest.target} required /></label>
            <label>Authorisation / ticket reference<input value={scanReference} onChange={event => setScanReference(event.target.value)} placeholder="Written approval or engagement reference" required maxLength={160} /></label>
            <label>TCP ports<input value={scanRequest.ports} onChange={event => setScanRequest(current => current ? { ...current, ports: event.target.value } : current)} required /></label>
            <div className="scope-checks"><label><input type="checkbox" checked={scanAuthorised} onChange={event => setScanAuthorised(event.target.checked)} /> I own this target or have explicit written permission to scan this exact target and these ports.</label></div>
            <button className="report-download" type="submit" disabled={scanBusy || !scanAuthorised || !scanReference.trim() || scanConfirmation.trim().toLowerCase() !== scanRequest.target.toLowerCase()}>{scanBusy ? "Running on Kali…" : "Confirm and run local Nmap scan"}</button>
            <button className="report-download" type="button" onClick={() => setScanRequest(null)} disabled={scanBusy}>Cancel</button>
          </form>
          {scanStatus && <p role="status">{scanStatus}</p>}
        </section>}
        {scanResult && <section className="network-results" style={{ marginTop: 16 }}><h2>Local Nmap results · {scanResult.target}</h2><p>{scanResult.duration_seconds}s · {scanResult.method}</p><p><strong>Open:</strong> {scanResult.state_summary.open} · <strong>Closed:</strong> {scanResult.state_summary.closed} · <strong>Filtered:</strong> {scanResult.state_summary.filtered}</p><div className="network-table-wrap"><table className="network-table"><thead><tr><th>Host</th><th>Port</th><th>Service</th><th>State</th><th>Product / version</th></tr></thead><tbody>{scanResult.hosts.flatMap((host, index) => host.ports.map(port => <tr key={index + "-" + port.port}><td>{host.addresses[0]?.address || scanResult.target}</td><td>{port.port}</td><td>{port.service}</td><td>{port.state}</td><td>{[port.product, port.version].filter(Boolean).join(" ") || "—"}</td></tr>))}</tbody></table></div><p>{scanResult.note}</p></section>}
        {scanStatus && !scanRequest && !scanResult && <div className="agent-error">{scanStatus}</div>}
        {error && <div className="agent-error"><CircleAlert size={14} /><span>{error}</span></div>}
        <form className="agent-composer" onSubmit={submit}>
          {attachments.length > 0 && <div className="agent-attachment-list">{attachments.map((file, index) => <div className="agent-attachment-chip" key={file.name + index}><FileText size={13}/><span>{file.name}</span><button type="button" aria-label={"Remove " + file.name} onClick={() => setAttachments(current => current.filter((_, i) => i !== index))}><X size={12}/></button></div>)}</div>}
          <textarea value={prompt} onChange={(event) => setPrompt(event.target.value)} placeholder="Describe what you want to investigate…" rows={3} maxLength={8000} disabled={busy} />
          <div className="agent-composer-bottom">
            <span><ShieldCheck size={12} /> Live research + passive IP/DNS/CVE · Local Nmap requires Kali pairing and explicit approval</span>
            <div className="agent-composer-actions">
              <input ref={fileInputRef} type="file" hidden multiple accept="image/png,image/jpeg,image/webp,image/gif,application/pdf,text/plain,text/markdown,text/csv,application/json,application/xml,.txt,.md,.csv,.json,.xml" onChange={event => void addFiles(event.target.files)} />
              <button type="button" className="agent-tool-button" onClick={() => fileInputRef.current?.click()} disabled={busy || attachments.length >= 4}><Paperclip size={14}/><span>Attach</span></button>
              <label className="agent-tool-button agent-audio-upload"><Mic size={14}/><span>{audioBusy ? "Transcribing…" : "Audio"}</span><input type="file" accept="audio/*" disabled={busy || audioBusy} onChange={event => { const file = event.target.files?.[0]; if (file) void transcribeAudio(file, true); event.target.value = ""; }}/></label>
              <button type="button" className={"agent-tool-button " + (recording ? "recording" : "")} onClick={() => void toggleRecording()} disabled={busy || audioBusy}>{recording ? <Square size={13}/> : <Mic size={14}/>}<span>{recording ? "Stop" : "Record"}</span></button>
              <button type="submit" disabled={busy || audioBusy || (!prompt.trim() && attachments.length === 0) || !model}>{busy ? <LoaderCircle size={14} className="spin" /> : <Send size={14} />} {busy ? "Working" : "Send"}</button>
            </div>
          </div>
        </form>
        <div className="agent-disclaimer"><Sparkles size={12} /> Open-weight mode does not mean unrestricted or guaranteed uncensored output. Outputs are AI-generated and must be verified against primary evidence. Use only on systems and data you are authorised to assess.</div>
      </section>
    </main>
  );
}