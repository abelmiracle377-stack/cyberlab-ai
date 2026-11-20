"use client";

import { FormEvent, useEffect, useRef, useState } from "react";
import { ArrowLeft, Bot, ChevronDown, CircleAlert, LoaderCircle, Send, ShieldCheck, Sparkles, Paperclip, Mic, Square, FileText, X } from "lucide-react";
import Link from "next/link";
import { planCompanionToolRequest, type CompanionToolRequest } from "../../lib/companion-tools";

type Model = { id: string; name: string; provider: string; contextLength: number | null; openWeight: boolean; uncensored?: boolean; supportsTools?: boolean; source: "openrouter" | "ollama" | "unfiltered" };
const modelKey = (item: Model) => `${item.source}::${item.id}`;
const matchesProvider = (item: Model, choice: "openrouter" | "ollama" | "auto") => choice === "auto" || (choice === "ollama" ? item.source === "ollama" : item.source !== "ollama");
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
  const [executionMode, setExecutionMode] = useState<"single" | "specialists">("single");
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
  const [toolRequest, setToolRequest] = useState<CompanionToolRequest | null>(null);
  const [toolAuth, setToolAuth] = useState("");
  const [toolTargetConfirm, setToolTargetConfirm] = useState("");
  const [toolWordlist, setToolWordlist] = useState("");
  const [toolBusy, setToolBusy] = useState(false);
  const [toolStatus, setToolStatus] = useState("");

  const endRef = useRef<HTMLDivElement>(null);
  const providerModels = models.filter((item) => matchesProvider(item, providerChoice));
  const selectedEntry = models.find((item) => modelKey(item) === model);
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
        const preferredSource = eligibleForMode.some((item) => item.source !== "ollama")
          ? "openrouter"
          : eligibleForMode.some((item) => item.source === "ollama") ? "ollama" : "openrouter";
        if (preferredSource === "ollama") setProviderChoice("ollama");
        setModel((current) => {
          const eligible = eligibleForMode.filter((item) => matchesProvider(item, preferredSource));
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
      if (typeof data.text !== "string" || !data.text.trim()) throw new Error("The transcription provider returned no text.");
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

  async function runCompanionTool(event: FormEvent) {
    event.preventDefault();
    if (!toolRequest || toolBusy) return;
    const token = sessionStorage.getItem("cyberlab.kaliBridgeToken");
    if (!token) { setToolStatus("Pair your local companion in Kali Connection first; the tool runs on your own machine."); return; }
    const parameters: Record<string, string | number> = { ...toolRequest.parameters };
    const missingParam = toolRequest.missing[0];
    if (missingParam) {
      if (!toolWordlist.trim()) { setToolStatus("Enter the required " + missingParam + " path on your paired machine."); return; }
      parameters[missingParam] = toolWordlist.trim();
    }
    const targetValue = toolRequest.targetParam ? String(parameters[toolRequest.targetParam] ?? "") : "";
    if (toolRequest.active) {
      if (!toolAuth.trim()) { setToolStatus("Active tools need a written authorisation/engagement reference."); return; }
      if (toolTargetConfirm.trim().toLowerCase() !== targetValue.trim().toLowerCase()) {
        setToolStatus("Retype the exact target to confirm you are authorised to assess it."); return;
      }
    }
    setToolBusy(true);
    setToolStatus("Running " + toolRequest.label + " on your paired companion…");
    try {
      const response = await fetch("http://127.0.0.1:8765/tools/run", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
        body: JSON.stringify({
          tool: toolRequest.tool, parameters, confirmRun: true,
          authorizationReference: toolAuth.trim(), targetConfirmation: targetValue,
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The companion rejected the tool run.");
      const request = toolRequest;
      setToolRequest(null);
      setToolStatus(data.status === "completed" ? "Tool finished (exit code " + data.exitCode + "). Analysing output…" : "Tool run " + data.status + ".");
      const evidence = {
        tool: request.tool, arguments: data.argv, exitCode: data.exitCode,
        status: data.status, stdout: (data.stdout || "").slice(0, 20000),
        stderr: (data.stderr || "").slice(0, 2000), truncated: data.truncated === true,
      };
      await sendAgentPrompt(
        "Analyse the output of this CyberLab companion tool run. Summarise the security-relevant findings, separate confirmed observations from leads, and recommend safe next steps. Do not claim results beyond this evidence.\n\n" + JSON.stringify(evidence),
        [], true);
    } catch (cause) {
      setToolStatus(cause instanceof Error ? cause.message : "Companion tool run failed.");
    } finally {
      setToolBusy(false);
    }
  }

  async function sendAgentPrompt(text: string, submittedAttachments: AgentAttachment[] = [], skipLocalRouting = false) {
    if ((!text && submittedAttachments.length === 0) || busy) return;
    if (submittedAttachments.length && (executionMode === "specialists" || selectedEntry?.uncensored)) {
      setError("File attachments are currently supported in standard single-agent mode. Switch from Specialist team or the unfiltered model to analyse attachments.");
      return;
    }
    setError("");
    setScanRequest(null);
    setScanStatus("");
    setScanResult(null);
    if (!skipLocalRouting) { setWebAssessmentRequest(null); setWebStatus(""); setWebResult(null); setToolRequest(null); setToolStatus(""); }
    setPrompt("");
    setAttachments([]);
    // Explicit tool instructions ("run whois/nikto/gobuster ...") take priority and
    // are proposed as a companion tool run the operator approves and executes.
    const plannedTool = !skipLocalRouting && submittedAttachments.length === 0 ? planCompanionToolRequest(text) : null;
    if (plannedTool) {
      setMessages((current) => [...current, { role: "user", content: text }, { role: "assistant", content: "I can run " + plannedTool.label + " on your paired companion. Review the parameters and approve below — nothing runs until you confirm." }]);
      setToolRequest(plannedTool);
      setToolAuth("");
      setToolTargetConfirm("");
      setToolWordlist(typeof plannedTool.parameters.wordlist === "string" ? plannedTool.parameters.wordlist : "");
      setToolStatus("");
      setBusy(false);
      return;
    }
    const webIntent = /\b(?:scan|crawl|test|assess|audit)\b[\s\S]{0,100}\b(?:https?:\/\/|website|web\s+app|web\s+application)\b|\b(?:website|web\s+app|web\s+application)\b[\s\S]{0,100}\b(?:scan|crawl|test|assess|audit)\b/i.test(text);
    const webTargetMatch = text.match(/https?:\/\/[^\s<>"']+|(?<![@\w-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::\d{1,5})?(?:\/[^\s<>"']*)?/i);
    if (!skipLocalRouting && webIntent && webTargetMatch && submittedAttachments.length === 0) {
      const rawTarget = webTargetMatch[0].replace(/[),.;]+$/, "");
      const targetUrl = /^https?:\/\//i.test(rawTarget) ? rawTarget : "https://" + rawTarget;
      try {
        const parsedTarget = new URL(targetUrl);
        if (!["http:", "https:"].includes(parsedTarget.protocol) || parsedTarget.username || parsedTarget.password || parsedTarget.hash) throw new Error("Use an HTTP(S) URL without embedded credentials or fragments.");
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
    if (!skipLocalRouting && scanMatch && submittedAttachments.length === 0) {
      const portsMatch = text.match(/\bports?\s+([0-9,-]+(?:\s*[-,]\s*[0-9]+)*)/i);
      setMessages((current) => [...current, { role: "user", content: text }, { role: "assistant", content: "I can prepare a bounded Nmap TCP scan on your paired local Kali machine. Before anything runs, confirm the exact target, authorisation reference and scope below. No scan has started." }]);
      setScanRequest({ target: scanMatch[1], ports: portsMatch?.[1]?.replace(/\s+/g, "") || "1-100" });
      setBusy(false);
      return;
    }
    setMessages((current) => [...current, { role: "user", content: text || ("Please analyse the attached file(s): " + submittedAttachments.map(file => file.name).join(", ")) }, { role: "assistant", content: "" }]);
    setBusy(true);
    try {
      if (selectedEntry?.uncensored) {
        const specialistMode = executionMode === "specialists";
        const selectedModel = selectedEntry;
        const useReadOnlyTools = !specialistMode && selectedModel?.supportsTools === true;
        const response = await fetch(specialistMode ? "/api/agent/uncensored/orchestrate" : useReadOnlyTools ? "/api/agent/uncensored/tools" : "/api/agent/uncensored", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            prompt: text,
            model: selectedEntry.id.slice("uncensored:".length),
            history: messages.filter((item) => item.content.trim()).slice(-12),
            maxSpecialists: 4,
          }),
        });
        if (!response.ok) {
          const data = await response.json();
          throw new Error(data.error || "Unfiltered model request failed.");
        }
        let output = "";
        if (specialistMode) {
          const data = await response.json();
          const specialistSummary = Array.isArray(data.results)
            ? data.results.map((item: any) => ["### " + item.label + " · " + item.status, item.analysis || item.error || "No analysis returned."].join("\n")).join("\n\n")
            : "";
          output = [data.synthesis || "The coordinator could not produce a synthesis.", specialistSummary, data.note || ""].filter(Boolean).join("\n\n---\n\n");
        } else if (useReadOnlyTools) {
          const data = await response.json();
          const evidenceText = Array.isArray(data.evidence) && data.evidence.length
            ? data.evidence.map((item: any) => [
                "### Evidence · " + String(item.tool || "tool"),
                "Observed: " + String(item.observedAt || "timestamp unavailable"),
                "Source: " + String(item.source || "unspecified"),
                String(item.summary || ""),
                "Evidence payload: " + JSON.stringify(item.data || {}).slice(0, 5000),
              ].join("\n")).join("\n\n")
            : "No external tool evidence was retrieved.";
          output = [data.text || "The model returned an empty response.", "## Tool evidence and provenance", evidenceText, "_Analysis is model-generated; tool results are read-only evidence snapshots._"].join("\n\n");
        } else {
          output = await response.text();
        }
        setMessages((current) => {
          const next = [...current];
          next[next.length - 1] = { role: "assistant", content: output || "The model returned an empty response." };
          return next;
        });
      } else if (executionMode === "specialists") {
        const response = await fetch("/api/agent/orchestrate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ prompt: text, model: selectedEntry?.id || "", maxSpecialists: 4, agentMode }),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Specialist orchestration failed.");
        const specialistSummary = Array.isArray(data.results)
          ? data.results.map((item: any) => ["### " + item.label + " · " + item.status, item.analysis || item.error || "No analysis returned."].join("\n")).join("\n\n")
          : "";
        const output = [data.synthesis || "The coordinator could not produce a synthesis.", specialistSummary, data.note || ""].filter(Boolean).join("\n\n---\n\n");
        setMessages((current) => {
          const next = [...current];
          next[next.length - 1] = { role: "assistant", content: output };
          return next;
        });
      } else {
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
      }
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
        <div className="flex flex-wrap items-center gap-2 rounded-xl border border-slate-800 bg-[#161B22] p-3">
          <span className="mr-2 text-[10px] tracking-wider text-slate-500">NATIVE WEB WORKFLOWS</span>
          <Link href="/web-crawler" className="rounded border border-emerald-900/70 px-3 py-2 text-xs text-emerald-300 hover:bg-emerald-950/30">Web discovery & baseline audit</Link>
          <Link href="/web-scanner" className="rounded border border-amber-900/70 px-3 py-2 text-xs text-amber-200 hover:bg-amber-950/30">Safe active checks</Link>
          <span className="text-[10px] text-slate-500">Local companion execution · separate approval required</span>
        </div>
        <div className="agent-config agent-config-stack">
          <div className="agent-mode-switch" role="group" aria-label="Execution mode">
            <button type="button" className={executionMode === "single" ? "selected" : ""} onClick={() => setExecutionMode("single")} disabled={busy}>Single agent</button>
            <button type="button" className={executionMode === "specialists" ? "selected" : ""} onClick={() => setExecutionMode("specialists")} disabled={busy}>Specialist team</button>
          </div>
          {executionMode === "specialists" && <p className="agent-disclaimer">Parallel role-conditioned analyses and coordinator synthesis use the selected model. These are not separate autonomous agents or independent evidence sources. Tool execution is not enabled in this mode.</p>}
          <div className="agent-mode-switch" role="group" aria-label="Agent mode">
            <button type="button" className={agentMode === "standard" ? "selected" : ""} onClick={() => { setAgentMode("standard"); const choices = models.filter((item) => matchesProvider(item, providerChoice)); if (!choices.some((item) => modelKey(item) === model)) { const preferred = choices.find((item) => item.id === "openai/gpt-5.5") || choices[0]; setModel(preferred ? modelKey(preferred) : ""); } }} disabled={busy}>Standard</button>
            <button type="button" className={agentMode === "open-weight" ? "selected" : ""} onClick={() => { const first = models.find((item) => item.openWeight && matchesProvider(item, providerChoice)); setAgentMode("open-weight"); if (first) setModel(modelKey(first)); }} disabled={busy}>Open-weight research mode</button>
          </div>
          <div className="agent-model-label"><span className="agent-live-dot" /> {selectedEntry?.uncensored ? "UNFILTERED MODEL ROUTING" : agentMode === "open-weight" ? "OPEN-WEIGHT MODEL ROUTING" : "MODEL ROUTING"}</div>
          <label className="agent-select-wrap">
            <span className="sr-only">Select provider</span>
            <select value={providerChoice} onChange={(event) => {
              const next = event.target.value as "openrouter" | "ollama" | "auto";
              setProviderChoice(next);
              const choices = models.filter((item) => matchesProvider(item, next));
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
              {availableModels.length ? availableModels.map((item) => <option value={modelKey(item)} key={modelKey(item)}>{item.name}{item.uncensored ? " · UNFILTERED" : ""} · {item.provider} · {item.source === "ollama" ? "LOCAL" : "CLOUD"}</option>) : <option value="">{providerChoice === "ollama" ? "No Ollama models discovered" : agentMode === "open-weight" ? "No recognised open-weight models available" : "No models available"}</option>}
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
              <p>The agent can research public sources and analyse IP/DNS intelligence and CVEs. Ask “scan example.com” for bounded Nmap TCP reconnaissance, or “scan my website https://example.com” for CyberLab’s native web crawler and optional safe active checks. Both wait for your explicit local approval.</p>
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
        {toolRequest && <section className="kali-panel" style={{ marginTop: 16 }}>
          <h2>Approve companion tool run</h2>
          <p>Tool: <strong>{toolRequest.label}</strong>. Parameters: <code>{Object.entries(toolRequest.parameters).filter(([k]) => k !== "wordlist").map(([k, v]) => k + "=" + v).join("  ")}</code>. This runs on your paired machine (127.0.0.1); nothing is sent to the CyberLab server.</p>
          <form className="report-editor" onSubmit={runCompanionTool}>
            {toolRequest.missing.length > 0 && <label>{toolRequest.missing[0]} path (on your machine)<input value={toolWordlist} onChange={event => setToolWordlist(event.target.value)} placeholder="/usr/share/wordlists/dirb/common.txt" required /></label>}
            {toolRequest.active && <>
              <label>Authorisation / engagement reference<input value={toolAuth} onChange={event => setToolAuth(event.target.value)} placeholder="Written authorisation to assess this target" required maxLength={200} /></label>
              <label>Retype exact target<input value={toolTargetConfirm} onChange={event => setToolTargetConfirm(event.target.value)} placeholder={toolRequest.targetParam ? String(toolRequest.parameters[toolRequest.targetParam] ?? "") : ""} required /></label>
              <div className="scope-checks"><label><input type="checkbox" required /> I own this target or have explicit written permission to assess it.</label></div>
            </>}
            <button className="report-download" type="submit" disabled={toolBusy}>{toolBusy ? "Running on companion…" : "Run on companion"}</button>
            <button className="report-download" type="button" onClick={() => setToolRequest(null)} disabled={toolBusy}>Cancel</button>
          </form>
          {toolStatus && <p role="status">{toolStatus}</p>}
        </section>}
        {toolStatus && !toolRequest && <div className="agent-error">{toolStatus}</div>}
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
          <textarea value={prompt} onChange={(event) => setPrompt(event.target.value)} placeholder="Describe what you want to investigate…" rows={3} maxLength={8000} disabled={busy || audioBusy} />
          {(attachments.length > 0 || audioBusy) && <p className="network-note">Files and audio are sent to the configured model/transcription provider for processing. Do not attach wallet seeds, private keys, passwords or recovery phrases.</p>}
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
        <div className="agent-disclaimer"><Sparkles size={12} /> Unfiltered models are separately configured hosted checkpoints; the label does not certify model behaviour. Outputs are AI-generated and must be verified against primary evidence. Tool execution and real-world actions remain separately permissioned.</div>
      </section>
    </main>
  );
}