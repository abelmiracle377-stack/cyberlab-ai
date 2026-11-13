export const runtime="nodejs";
export const dynamic="force-dynamic";
export async function POST(request:Request){
 try{
  const body=await request.json();const domain=String(body.domain||"").trim().toLowerCase().replace(/\.$/,"");
  if(!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain))return Response.json({error:"Enter a valid domain name."},{status:400});
  const params=new URLSearchParams({url:"*."+domain,output:"json",fl:"original,timestamp,statuscode,mimetype",filter:"statuscode:200",collapse:"urlkey",limit:"100"});
  const response=await fetch("https://web.archive.org/cdx/search/cdx?"+params.toString(),{headers:{"User-Agent":"CyberLabAI/1.0 (public historical URL research)"},signal:AbortSignal.timeout(15000),cache:"no-store"});
  if(!response.ok)return Response.json({error:"Internet Archive CDX returned HTTP "+response.status+"."},{status:502});
  const rows=await response.json();const entries=Array.isArray(rows)?rows.slice(1).map((row:unknown[])=>({url:row[0],timestamp:row[1],status:row[2],mime:row[3],archiveUrl:"https://web.archive.org/web/"+row[1]+"/"+row[0]})): [];
  return Response.json({domain,total:entries.length,entries,source:"Internet Archive CDX API",generatedAt:new Date().toISOString(),note:"Historical captures are public archive records, not proof that a URL is currently live or safe. Review destinations before opening them."},{headers:{"Cache-Control":"no-store"}});
 }catch{return Response.json({error:"Historical URL lookup failed or timed out."},{status:502})}
}
