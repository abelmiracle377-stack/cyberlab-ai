import { isIP } from "node:net";
import { resolve4, resolve6, resolveMx, resolveNs, resolveTxt } from "node:dns/promises";
import { timingSafeEqual } from "node:crypto";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const tools = [
 {name:"ip_intelligence",description:"Retrieve public IP registration and network context. Does not identify a person.",inputSchema:{type:"object",properties:{ip:{type:"string",description:"IPv4 or IPv6 address"}},required:["ip"],additionalProperties:false}},
 {name:"dns_intelligence",description:"Resolve public-domain A, AAAA, MX, NS and TXT records using passive DNS.",inputSchema:{type:"object",properties:{domain:{type:"string",description:"Domain name without URL or path"}},required:["domain"],additionalProperties:false}},
 {name:"cve_lookup",description:"Search NIST NVD for a CVE ID or product keyword; returns summaries and CVSS context.",inputSchema:{type:"object",properties:{query:{type:"string",minLength:3,maxLength:120}},required:["query"],additionalProperties:false}},
];

function authorised(request:Request) {
 const expected=process.env.CYBERLAB_MCP_API_KEY;
 const supplied=request.headers.get("authorization")?.replace(/^Bearer\s+/i,"") || "";
 if(!expected || !supplied) return false;
 const a=Buffer.from(expected), b=Buffer.from(supplied);
 return a.length===b.length && timingSafeEqual(a,b);
}
function rpc(id:unknown,result:unknown){return Response.json({jsonrpc:"2.0",id,result},{headers:{"Cache-Control":"no-store"}})}
function error(id:unknown,code:number,message:string){return Response.json({jsonrpc:"2.0",id,error:{code,message}},{status:200,headers:{"Cache-Control":"no-store"}})}
async function callTool(name:string,args:Record<string,unknown>) {
 if(name==="ip_intelligence"){
  const ip=String(args.ip||""); if(!isIP(ip)) throw new Error("A valid IPv4 or IPv6 address is required.");
  const response=await fetch("https://ipwho.is/"+encodeURIComponent(ip),{signal:AbortSignal.timeout(8000),cache:"no-store"});
  if(!response.ok) throw new Error("IP intelligence provider unavailable.");
  const data=await response.json(); if(data.success===false) throw new Error(data.message||"Lookup failed.");
  return {ip:data.ip,type:data.type,country:data.country,region:data.region,city:data.city,connection:{isp:data.connection?.isp,organization:data.connection?.org,asn:data.connection?.asn},source:"ipwho.is",note:"Approximate network registration context; not personal identity or exact location."};
 }
 if(name==="dns_intelligence"){
  const domain=String(args.domain||"").toLowerCase().replace(/\.$/,"");
  if(!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) throw new Error("A valid domain name is required.");
  const resolve=async(fn:(d:string)=>Promise<unknown>)=>{try{return await fn(domain)}catch(e){const c=(e as NodeJS.ErrnoException).code;return c==="ENODATA"||c==="ENOTFOUND"?[]:{error:c||"DNS_ERROR"}}};
  const [a,aaaa,mx,ns,txt]=await Promise.all([resolve(resolve4),resolve(resolve6),resolve(resolveMx),resolve(resolveNs),resolve(resolveTxt)]);
  return {domain,records:{A:a,AAAA:aaaa,MX:mx,NS:ns,TXT:txt},source:"System DNS resolver"};
 }
 if(name==="cve_lookup"){
  const query=String(args.query||"").trim(); if(query.length<3||query.length>120) throw new Error("Query must be 3–120 characters.");
  const params=new URLSearchParams({resultsPerPage:"5"});
  if(/^CVE-\d{4}-\d{4,}$/i.test(query)) params.set("cveId",query.toUpperCase()); else params.set("keywordSearch",query);
  const response=await fetch("https://services.nvd.nist.gov/rest/json/cves/2.0?"+params,{signal:AbortSignal.timeout(10000),cache:"no-store"});
  if(!response.ok) throw new Error("NVD returned HTTP "+response.status);
  const data=await response.json();
  return {query,totalResults:data.totalResults,results:(data.vulnerabilities||[]).map((entry:any)=>{const c=entry.cve;const d=c.metrics?.cvssMetricV31?.[0]?.cvssData??c.metrics?.cvssMetricV30?.[0]?.cvssData??c.metrics?.cvssMetricV40?.[0]?.cvssData;return{id:c.id,published:c.published,modified:c.lastModified,description:c.descriptions?.find((x:any)=>x.lang==="en")?.value,cvss:d?{version:d.version,score:d.baseScore,severity:d.baseSeverity}:null,references:(c.references||[]).slice(0,4).map((x:any)=>x.url)}}),source:"NIST National Vulnerability Database",note:"A CVE match does not prove a specific asset is vulnerable."};
 }
 throw new Error("Tool not found or not enabled.");
}
export async function GET(request:Request){
 if(!authorised(request)) return Response.json({error:"MCP gateway is disabled or authentication failed."},{status:process.env.CYBERLAB_MCP_API_KEY?401:503});
 return Response.json({name:"CyberLab AI MCP Gateway",version:"0.1.0",protocol:"JSON-RPC 2.0",endpoint:"POST /api/mcp",authentication:"Bearer CYBERLAB_MCP_API_KEY",tools:tools.map(t=>t.name)});
}
export async function POST(request:Request){
 if(!authorised(request)) return Response.json({error:"MCP gateway is disabled or authentication failed."},{status:process.env.CYBERLAB_MCP_API_KEY?401:503});
 let body:any; try{body=await request.json()}catch{return error(null,-32700,"Parse error")}
 const id=body?.id??null; if(body?.jsonrpc!=="2.0"||typeof body.method!=="string") return error(id,-32600,"Invalid Request");
 if(body.method==="initialize") return rpc(id,{protocolVersion:"2025-03-26",capabilities:{tools:{}},serverInfo:{name:"cyberlab-ai",version:"0.1.0"}});
 if(body.method==="notifications/initialized") return new Response(null,{status:202});
 if(body.method==="ping") return rpc(id,{});
 if(body.method==="tools/list") return rpc(id,{tools});
 if(body.method==="tools/call"){
  const name=body.params?.name; const args=body.params?.arguments||{};
  if(typeof name!=="string"||!args||typeof args!=="object"||Array.isArray(args)) return error(id,-32602,"Invalid tool arguments");
  try{const result=await callTool(name,args);return rpc(id,{content:[{type:"text",text:JSON.stringify(result)}],structuredContent:result,isError:false})}
  catch(e){return rpc(id,{content:[{type:"text",text:(e as Error).message}],isError:true})}
 }
 return error(id,-32601,"Method not found");
}
