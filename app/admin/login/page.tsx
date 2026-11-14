"use client";
import {FormEvent,useState} from "react";
import {useRouter} from "next/navigation";
import {ShieldCheck} from "lucide-react";
import {createClient} from "@/lib/supabase/client";

export default function AdminLoginPage(){
 const router=useRouter();const[email,setEmail]=useState("");const[password,setPassword]=useState("");const[busy,setBusy]=useState(false);const[error,setError]=useState("");
 async function submit(e:FormEvent){e.preventDefault();setBusy(true);setError("");try{const supabase=createClient();const {error:authError}=await supabase.auth.signInWithPassword({email,password});if(authError)throw authError;const r=await fetch("/api/admin/auth",{cache:"no-store"});if(!r.ok){await supabase.auth.signOut();throw new Error("This account is not an approved administrator.");}router.replace("/admin");router.refresh();}catch(x){setError(x instanceof Error?x.message:"Administrator sign-in failed.");}finally{setBusy(false);}}
 const field={width:"100%",padding:12,borderRadius:7,border:"1px solid #35443a",background:"#0c120e",color:"#e8eee9"};
 return <main style={{minHeight:"100vh",display:"grid",placeItems:"center",padding:22,background:"#080b09",color:"#e8eee9"}}><section style={{width:"100%",maxWidth:420,padding:30,border:"1px solid #344638",borderRadius:12,background:"#101711"}}><div style={{display:"flex",gap:10,alignItems:"center",color:"#b8d8b9"}}><ShieldCheck/><span style={{fontSize:11,letterSpacing:2}}>CYBERLAB AI / ADMINISTRATOR</span></div><h1 style={{fontSize:28,margin:"25px 0 8px"}}>Admin sign in</h1><p style={{color:"#9ba99e",lineHeight:1.6}}>Restricted access for approved administrators only.</p><form onSubmit={submit} style={{display:"grid",gap:14,marginTop:24}}><label style={{display:"grid",gap:7,fontSize:12}}>Admin email<input type="email" required autoComplete="username" value={email} onChange={e=>setEmail(e.target.value)} style={field}/></label><label style={{display:"grid",gap:7,fontSize:12}}>Password<input type="password" required autoComplete="current-password" value={password} onChange={e=>setPassword(e.target.value)} style={field}/></label>{error&&<p role="alert" style={{color:"#e9a5a5",fontSize:13}}>{error}</p>}<button disabled={busy} style={{padding:13,borderRadius:7,border:"1px solid #63846a",background:"#23452c",color:"white",fontWeight:700}}>{busy?"Verifying…":"Sign in to admin"}</button></form></section></main>;
}
