import {NextResponse} from "next/server";
import {adminGate} from "@/lib/billing/admin";
export const dynamic="force-dynamic";
export async function GET(){
 const g=await adminGate(); if(g.error)return g.error;
 const {data,error}=await g.db!.from("knowledge_items").select("*").order("created_at",{ascending:false}).limit(1000);
 if(error)return NextResponse.json({error:error.message},{status:500});
 return NextResponse.json({entries:data||[]});
}
export async function POST(req:Request){
 const g=await adminGate(); if(g.error)return g.error;
 const b=await req.json().catch(()=>({}));
 if(typeof b.title!=="string"||!b.title.trim()||typeof b.content!=="string"||!b.content.trim())return NextResponse.json({error:"Title and content are required."},{status:400});
 if(b.title.length>200||b.content.length>30000)return NextResponse.json({error:"Title limit is 200 characters; content limit is 30,000."},{status:400});
 const status=b.status==="approved"||b.status==="rejected"?"pending": "pending";
 const {data,error}=await g.db!.from("knowledge_items").insert({title:b.title.trim(),category:typeof b.category==="string"?b.category.slice(0,80):"Other",source:typeof b.source==="string"?b.source.slice(0,120):"Analyst note",tags:typeof b.tags==="string"?b.tags.slice(0,500):"",content:b.content.trim(),status,created_by:g.user!.id}).select("*").single();
 if(error)return NextResponse.json({error:error.message},{status:500});
 return NextResponse.json({entry:data},{status:201});
}
export async function PATCH(req:Request){
 const g=await adminGate(); if(g.error)return g.error;
 const b=await req.json().catch(()=>({}));
 if(typeof b.id!=="string"||!["pending","approved","rejected"].includes(b.status))return NextResponse.json({error:"A valid item ID and status are required."},{status:400});
 const {data,error}=await g.db!.from("knowledge_items").update({status:b.status,updated_at:new Date().toISOString()}).eq("id",b.id).select("*").maybeSingle();
 if(error)return NextResponse.json({error:error.message},{status:500});
 if(!data)return NextResponse.json({error:"Knowledge item not found."},{status:404});
 return NextResponse.json({entry:data});
}
export async function DELETE(req:Request){
 const g=await adminGate(); if(g.error)return g.error;
 const {searchParams}=new URL(req.url);const id=searchParams.get("id");
 if(!id)return NextResponse.json({error:"Item ID required."},{status:400});
 const {error}=await g.db!.from("knowledge_items").delete().eq("id",id);
 if(error)return NextResponse.json({error:error.message},{status:500});
 return NextResponse.json({success:true});
}