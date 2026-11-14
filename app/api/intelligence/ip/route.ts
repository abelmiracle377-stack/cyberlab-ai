import { isIP } from "node:net";
import { promises as dns } from "node:dns";
export const runtime = "nodejs";
function isPublicIp(ip: string, version: number) {
 if (version === 4) {
  const p=ip.split(".").map(Number); const a=p[0], b=p[1];
  if (a===0||a===10||a===127||a>=224) return false;
  if (a===169&&b===254) return false;
  if (a===172&&b>=16&&b<=31) return false;
  if (a===192&&b===168) return false;
  if (a===100&&b>=64&&b<=127) return false;
  if (a===192&&b===0&&p[2]===0) return false;
  if (a===198&&(b===18||b===19)) return false;
  if (a===198&&b===51&&p[2]===100) return false;
  if (a===203&&b===0&&p[2]===113) return false;
  return true;
 }
 const n=ip.toLowerCase();
 if (n==="::"||n==="::1"||n.startsWith("fc")||n.startsWith("fd")||n.startsWith("fe8")||n.startsWith("fe9")||n.startsWith("fea")||n.startsWith("feb")||n.startsWith("ff")) return false;
 return n.startsWith("2")||n.startsWith("3");
}
export async function POST(request: Request) {
 let body: unknown;
 try { body=await request.json(); } catch { return Response.json({error:"Invalid JSON request."},{status:400}); }
 const raw=body&&typeof body==="object"&&"ip" in body?(body as {ip?:unknown}).ip:null;
 const ip=typeof raw==="string"?raw.trim():""; const version=isIP(ip);
 if (!version) return Response.json({error:"Enter a valid IPv4 or IPv6 address."},{status:400});
 if (!isPublicIp(ip,version)) return Response.json({error:"Private, loopback, link-local and reserved IP ranges are not queried by this public intelligence service."},{status:400});
 try {
  const response=await fetch("https://ipwho.is/"+encodeURIComponent(ip),{headers:{"Accept":"application/json","User-Agent":"CyberLabAI-IP-Intel/1.0"},signal:AbortSignal.timeout(8000),cache:"no-store"});
  if(!response.ok) return Response.json({error:"IP intelligence provider returned HTTP "+response.status+"."},{status:502});
  const data=await response.json();
  if(data.success===false) return Response.json({error:String(data.message||"Provider could not resolve this IP address.")},{status:404});
  let reverseDns:string[]=[];
  try { reverseDns=await dns.reverse(ip); } catch { reverseDns=[]; }
  return Response.json({
   ip:String(data.ip||ip),version:String(data.type||("IPv"+version)),
   location:{continent:data.continent||null,country:data.country||null,region:data.region||null,city:data.city||null,latitude:typeof data.latitude==="number"?data.latitude:null,longitude:typeof data.longitude==="number"?data.longitude:null},
   network:{asn:data.connection?.asn??null,org:data.connection?.org??null,isp:data.connection?.isp??null,domain:data.connection?.domain??null},
   timezone:data.timezone?.utc||null,reverseDns,
   note:"Geolocation is approximate and describes network registration or routing context, not a device's precise location or a person's identity. VPNs, proxies, mobile networks and hosting providers can affect results."
  });
 } catch { return Response.json({error:"The public IP intelligence provider timed out or could not be reached."},{status:502}); }
}
