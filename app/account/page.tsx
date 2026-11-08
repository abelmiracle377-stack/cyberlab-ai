import Link from "next/link";
import { createClient } from "@/lib/supabase/server";
import SignOutButton from "./signout-button";

export default async function AccountPage() {
  const configured = Boolean(process.env.NEXT_PUBLIC_SUPABASE_URL && process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY);
  if (!configured) return <main style={{ minHeight: "100vh", padding: 32, background: "#0c100e", color: "#e8eee9" }}><section style={{ maxWidth: 620, margin: "50px auto", padding: 28, border: "1px solid #29362f", borderRadius: 12, background: "#121a15" }}><Link href="/" style={{ color: "#a8c5af" }}>← Dashboard</Link><h1 style={{ fontSize: 26, marginTop: 25 }}>Account setup</h1><p style={{ color: "#aab9af", lineHeight: 1.7 }}>Supabase authentication is implemented but not activated. Add NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_ANON_KEY to the Vercel project environment variables, then redeploy to enable sign-in and protected workspace routes.</p><Link href="/login" style={{ color: "#a8c5af" }}>Open sign-in page</Link></section></main>;
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  return <main style={{ minHeight: "100vh", padding: 32, background: "#0c100e", color: "#e8eee9" }}><section style={{ maxWidth: 620, margin: "50px auto", padding: 28, border: "1px solid #29362f", borderRadius: 12, background: "#121a15" }}><Link href="/" style={{ color: "#a8c5af" }}>← Dashboard</Link><h1 style={{ fontSize: 26, marginTop: 25 }}>Account</h1><p style={{ color: "#aab9af" }}>Signed in as</p><strong>{user?.email || "No authenticated user"}</strong><div style={{ marginTop: 25 }}><SignOutButton /></div></section></main>;
}
