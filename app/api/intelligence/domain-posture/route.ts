import { resolve4,resolve6,resolveMx,resolveNs,resolveTxt,resolveCaa } from "node:dns/promises";
export const runtime="nodejs";
export const dynamic="force-dynamic";
const validDomain=(value:string)=>/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(value);
async function safe<T>(fn:()=>Promise<T>):Promise<T|{error:string}>{try{return await fn()}catch(e){const code=(e as NodeJS.ErrnoException).code;if(code==="ENODATA"||code==="ENOTFOUND")return [] as unknown as T;return {error:code||"DNS_LOOKUP_FAILED"}}}
export async function POST(request:Request){
 try{
  const body=await request.json();const domain=String(body.domain||"").trim().toLowerCase().replace(/\.$/,"");
  if(!validDomain(domain))return Response.json({error:"Enter a valid domain name without a URL or path."},{status:400});
  const selectors=["default","google","selector1","selector2","k1","s1"];
  const [a,aaaa,mx,ns,txt,caa,spf,dmarc,dkim]=await Promise.all([
   safe(()=>resolve4(domain)),safe(()=>resolve6(domain)),safe(()=>resolveMx(domain)),safe(()=>resolveNs(domain)),safe(()=>resolveTxt(domain)),safe(()=>resolveCaa(domain)),
   safe(()=>resolveTxt(domain)),safe(()=>resolveTxt("_dmarc."+domain)),
   Promise.all(selectors.map(async selector=>({selector,records:await safe(()=>resolveTxt(selector+"._domainkey."+domain))})))
  ]);
  const txtRows=Array.isArray(txt)?txt.map((x:any)=>Array.isArray(x)?x.join(""):String(x)):[];
  const spfRows=txtRows.filter(x=>/^v=spf1\b/i.test(x));
  const dmarcRows=Array.isArray(dmarc)?dmarc.map((x:any)=>Array.isArray(x)?x.join(""):String(x)).filter(x=>/^v=DMARC1\b/i.test(x)):[];
  const dkimRows=dkim.filter(x=>Array.isArray(x.records)&&x.records.some((record:any)=>Array.isArray(record)?record.join("").length>0:Array.isArray(record)===false&&typeof record==="string"));
  const checks=[
   {id:"spf",label:"SPF",status:spfRows.length?"present":"missing-or-unresolved",detail:spfRows.length?"SPF TXT record found. Review its mechanisms and lookup limits.":"No SPF record was found at the domain apex."},
   {id:"dmarc",label:"DMARC",status:dmarcRows.length?"present":"missing-or-unresolved",detail:dmarcRows.length?"DMARC policy record found. Review p=, rua= and alignment.":"No DMARC TXT record was found at _dmarc."},
   {id:"dkim",label:"DKIM",status:dkimRows.length?"selector-found":"not-confirmed",detail:dkimRows.length?"A common DKIM selector returned a record. This is not an exhaustive selector search.":"No records found for the small common-selector list; DKIM may use another selector."},
   {id:"mx",label:"Mail exchangers",status:Array.isArray(mx)&&mx.length?"present":"missing-or-unresolved",detail:Array.isArray(mx)&&mx.length?"MX records were returned.":"No MX records were returned."},
   {id:"caa",label:"CAA",status:Array.isArray(caa)&&caa.length?"present":"missing-or-unresolved",detail:Array.isArray(caa)&&caa.length?"CAA records were returned.":"No CAA records were returned."}
  ];
  return Response.json({domain,records:{A:a,AAAA:aaaa,MX:mx,NS:ns,CAA:caa,TXT:txt},mail:{SPF:spfRows,DMARC:dmarcRows,DKIM:dkim},checks,generatedAt:new Date().toISOString(),source:"Node.js system DNS resolver",limitations:"DNS records are point-in-time resolver observations. DKIM checks only six common selectors. Missing records can reflect DNS propagation or resolver behaviour; this is not a full mail-security audit."},{headers:{"Cache-Control":"no-store"}});
 }catch{return Response.json({error:"Domain posture lookup failed."},{status:500})}
}
