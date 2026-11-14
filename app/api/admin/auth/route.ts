import {NextResponse} from "next/server";
import {createClient} from "@/lib/supabase/server";
import {adminDb} from "@/lib/billing/admin";
export const dynamic="force-dynamic";
export async function GET(){const supabase=await createClient();const {data:{user}}=await supabase.auth.getUser();if(!user)return NextResponse.json({error:"Not found"},{status:404});const db=adminDb();const {data}=await db.from("user_profiles").select("role").eq("user_id",user.id).maybeSingle();if(data?.role!=="admin")return NextResponse.json({error:"Not found"},{status:404});return NextResponse.json({approved:true});}
