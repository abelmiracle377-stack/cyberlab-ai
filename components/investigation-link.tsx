"use client";

import { useEffect, useState } from "react";
import { Link2, LoaderCircle, ShieldCheck } from "lucide-react";

type CaseOption = { id: string; title: string; status: string };
type Props = {
  source: string;
  eventType: string;
  title: string;
  severity?: "informational" | "low" | "medium" | "high" | "critical";
  details: Record<string, unknown>;
};

export default function InvestigationLink({ source, eventType, title, severity = "informational", details }: Props) {
  const [cases, setCases] = useState<CaseOption[]>([]);
  const [selected, setSelected] = useState("");
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");

  async function loadCases() {
    setLoading(true);
    setMessage("");
    try {
      const response = await fetch("/api/investigations", { cache: "no-store" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not load investigation cases.");
      const available = (data.cases || []).filter((item: CaseOption) => !["closed", "resolved"].includes(item.status));
      setCases(available);
      if (!selected && available[0]) setSelected(available[0].id);
      if (!available.length) setMessage("No open cases found. Create one in Investigations first.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Investigation storage is unavailable.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void loadCases(); }, []);

  async function attach() {
    if (!selected) return;
    setSaving(true);
    setMessage("");
    try {
      const response = await fetch(`/api/investigations/${selected}/events`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ source, event_type: eventType, title, severity, details }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not attach finding.");
      setMessage("Evidence added to the investigation timeline.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not attach evidence.");
    } finally {
      setSaving(false);
    }
  }

  return <section className="kali-panel" aria-label="Investigation timeline">
    <h2><Link2 size={15} /> Add to investigation</h2>
    <p>Analyst-controlled action: attach this module's current result and its source context to a persistent case.</p>
    <div className="report-editor">
      <label>Open investigation
        <select value={selected} onChange={event => setSelected(event.target.value)} disabled={loading || !cases.length}>
          <option value="">Select a case</option>
          {cases.map(item => <option key={item.id} value={item.id}>{item.title} · {item.status}</option>)}
        </select>
      </label>
      <button className="report-download" type="button" onClick={attach} disabled={!selected || saving || loading}>
        {saving ? <><LoaderCircle size={14}/> Attaching…</> : <><ShieldCheck size={14}/> Attach evidence</>}
      </button>
      <button className="report-download" type="button" onClick={() => void loadCases()} disabled={loading}>Refresh cases</button>
    </div>
    {message && <p className="network-note" role="status">{message}</p>}
  </section>;
}
