import {createHmac,timingSafeEqual} from "node:crypto";import {NextResponse} from "next/server";import {adminDb} from "@/lib/billing/admin";
export const runtime="nodejs";
export async function POST(req:Request){
 const secret=process.env.PAYSTACK_SECRET_KEY;if(!secret)return NextResponse.json({error:"Webhook unavailable."},{status:503});
 const raw=await req.text(),sig=req.headers.get("x-paystack-signature")||"",expected=createHmac("sha512",secret).update(raw).digest("hex"),a=Buffer.from(sig),b=Buffer.from(expected);
 if(a.length!==b.length||!timingSafeEqual(a,b))return NextResponse.json({error:"Invalid signature."},{status:401});
 const event=JSON.parse(raw),db=adminDb(),d=event.data||{};
 const email=typeof d.customer?.email==="string"?d.customer.email:null;
 let userId:string|null=null;
 if(email){const {data:p}=await db.from("user_profiles").select("user_id").eq("email",email).maybeSingle();userId=p?.user_id||null;}
 if(event.event==="subscription.create"&&userId){
  await db.from("subscriptions").upsert({user_id:userId,provider:"paystack",provider_subscription_code:d.subscription_code||null,provider_customer_code:d.customer?.customer_code||null,plan_code:d.plan?.plan_code||process.env.PAYSTACK_PLAN_CODE||"",status:d.status==="active"?"active":"pending",amount:1000,currency:"USD",interval:"monthly"},{onConflict:"user_id"});
 }
 if(event.event==="charge.success"&&d.status==="success"&&d.currency==="USD"&&Number(d.amount)>=1000){
  const ref=typeof d.reference==="string"?d.reference:null;
  let payment:any=null;
  if(ref){const {data:p}=await db.from("payments").select("*").eq("provider_reference",ref).maybeSingle();payment=p;}
  if(!userId&&payment)userId=payment.user_id;
  if(userId&&(!d.metadata?.user_id||d.metadata.user_id===userId)){
   const now=new Date(),end=new Date(now);end.setMonth(end.getMonth()+1);
   const {data:sub}=await db.from("subscriptions").upsert({user_id:userId,provider:"paystack",provider_subscription_code:d.subscription?.subscription_code||undefined,provider_customer_code:d.customer?.customer_code||null,plan_code:process.env.PAYSTACK_PLAN_CODE||"",status:"active",amount:1000,currency:"USD",interval:"monthly",current_period_start:now.toISOString(),current_period_end:end.toISOString()},{onConflict:"user_id"}).select("id").single();
   if(ref){await db.from("payments").upsert({user_id:userId,subscription_id:sub?.id,provider:"paystack",provider_reference:ref,provider_transaction_id:String(d.id||""),amount:Number(d.amount),currency:d.currency,status:"success",paid_at:d.paid_at||now.toISOString(),raw_event:d},{onConflict:"provider_reference"});}
  }
 }
 if(event.event==="invoice.payment_failed"&&userId)await db.from("subscriptions").update({status:"past_due"}).eq("user_id",userId);
 if(event.event==="subscription.disable"&&userId)await db.from("subscriptions").update({status:"cancelled"}).eq("user_id",userId);
 return NextResponse.json({received:true});
}