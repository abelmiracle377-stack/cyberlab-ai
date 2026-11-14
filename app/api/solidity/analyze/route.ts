import { analyzeSoliditySource } from "@/lib/solidity-static-analysis";
export const runtime = "nodejs";
export const maxDuration = 10;
export async function POST(request:Request){
 let body:unknown;
 const length=request.headers.get("content-length");
 if(length!==null&&(!/^\d+$/.test(length)||Number(length)>110000))return Response.json({error:"Request body exceeds the 110 KB limit."},{status:413});
 try{body=await request.json()}catch{return Response.json({error:"Request body must be valid JSON."},{status:400})}
 if(!body||typeof body!=="object"||typeof (body as {source?:unknown}).source!=="string")return Response.json({error:"A Solidity source string is required."},{status:400});
 const source=(body as {source:string}).source;
 if(source.length>100000)return Response.json({error:"Solidity source exceeds the 100 KB limit."},{status:413});
 try{return Response.json({analysis:analyzeSoliditySource(source),sourceBytes:new TextEncoder().encode(source).byteLength},{headers:{"Cache-Control":"no-store"}})}
 catch(error){return Response.json({error:error instanceof Error?error.message:"Static analysis failed."},{status:400})}
}
