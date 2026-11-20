"use client";

import { FormEvent, Suspense, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { createClient } from "@/lib/supabase/client";
import { ShieldCheck } from "lucide-react";

export default function LoginPage() {
  return <Suspense fallback={<main style={{ minHeight: "100vh", display: "grid", placeItems: "center", background: "#0D1117", color: "#E6EDF3" }}>Loading sign-in…</main>}><LoginForm /></Suspense>;
}

function LoginForm() {
  const router = useRouter();
  const search = useSearchParams();
  const [mode, setMode] = useState<"signin" | "signup">(search.get("mode") === "signup" ? "signup" : "signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(search.get("error") || "");
  const [message, setMessage] = useState("");
  const configured = Boolean(process.env.NEXT_PUBLIC_SUPABASE_URL && process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY);

  async function submit(event: FormEvent) {
    event.preventDefault(); setError(""); setMessage(""); setBusy(true);
    try {
      const supabase = createClient();
      if (mode === "signin") {
        const { error: authError } = await supabase.auth.signInWithPassword({ email: email.trim().toLowerCase(), password });
        if (authError) throw authError;
        const requested = search.get("next") || "/";
        const destination = requested.startsWith("/") && !requested.startsWith("//") && !requested.includes("\\\\") ? requested : "/";
        router.replace(destination); router.refresh();
      } else {
        const { data, error: authError } = await supabase.auth.signUp({ email: email.trim().toLowerCase(), password, options: { emailRedirectTo: window.location.origin + "/auth/callback" } });
        if (authError) throw authError;
        if (data.session) { router.replace("/"); router.refresh(); }
        else { setMessage("Account created. Check your email to confirm your address, then sign in."); setMode("signin"); }
      }
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Authentication failed."); }
    finally { setBusy(false); }
  }

  const fieldStyle = { width: "100%", padding: "12px 13px", borderRadius: 7, border: "1px solid #30363D", background: "#0D1117", color: "#E6EDF3", outline: "none" };
  const buttonStyle = { width: "100%", padding: 13, borderRadius: 7, border: "1px solid #2EA043", background: "#2EA043", color: "#07140a", cursor: "pointer", fontWeight: 700 };

  return <main style={{ minHeight: "100vh", display: "grid", placeItems: "center", padding: 24, background: "#0D1117", color: "#E6EDF3" }}>
    <section style={{ width: "100%", maxWidth: 430, border: "1px solid #30363D", borderRadius: 14, padding: 30, background: "#161B22" }}>
      <Link href="/" style={{ color: "#8B949E", textDecoration: "none", fontSize: 13 }}>← CyberLab AI</Link>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginTop: 28 }}><ShieldCheck size={24}/><span style={{ letterSpacing: 2, fontSize: 12 }}>CYBERLAB AI</span></div>
      <h1 style={{ fontSize: 27, margin: "22px 0 8px" }}>{mode === "signin" ? "Welcome back" : "Create your account"}</h1>
      <p style={{ color: "#8B949E", fontSize: 14, lineHeight: 1.6 }}>Sign in to your private security research workspace.</p>
      {!configured ? <div style={{ marginTop: 22, padding: 14, border: "1px solid #D29922", borderRadius: 8, color: "#D29922", fontSize: 13, lineHeight: 1.6 }}>Authentication setup is incomplete. Add <code>NEXT_PUBLIC_SUPABASE_URL</code> and <code>NEXT_PUBLIC_SUPABASE_ANON_KEY</code> to Vercel Environment Variables, then redeploy. Never put a service-role key in the browser or GitHub.</div> : <form onSubmit={submit} style={{ display: "grid", gap: 13, marginTop: 22 }}>
        <label style={{ display: "grid", gap: 6, fontSize: 12, color: "#8B949E" }}>Email address<input type="email" required autoComplete="email" value={email} onChange={e=>setEmail(e.target.value)} style={fieldStyle}/></label>
        <label style={{ display: "grid", gap: 6, fontSize: 12, color: "#8B949E" }}>Password<input type="password" required minLength={8} autoComplete={mode === "signin" ? "current-password" : "new-password"} value={password} onChange={e=>setPassword(e.target.value)} style={fieldStyle}/></label>
        {error && <p role="alert" style={{ color: "#F85149", fontSize: 13 }}>{error}</p>}{message && <p role="status" style={{ color: "#3FB950", fontSize: 13 }}>{message}</p>}
        <button type="submit" disabled={busy} style={buttonStyle}>{busy ? "Please wait…" : mode === "signin" ? "Sign in" : "Create account"}</button>
      </form>}
      {configured && <button type="button" onClick={()=>{setMode(mode === "signin" ? "signup" : "signin");setError("");setMessage("");}} style={{ marginTop: 18, width: "100%", border: 0, background: "transparent", color: "#58A6FF", cursor: "pointer", padding: 8 }}>{mode === "signin" ? "Need an account? Create one" : "Already registered? Sign in"}</button>}
    </section>
  </main>;
}
