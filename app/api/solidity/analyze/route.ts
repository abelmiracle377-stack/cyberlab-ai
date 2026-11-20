import { analyzeSoliditySource } from "@/lib/solidity-static-analysis";
export const runtime = "nodejs";
export const maxDuration = 10;
async function readBoundedBody(request:Request):Promise<unknown>{
 const length=request.headers.get("content-length");
 if(length!==null&&(!/^\d+$/.test(length)||Number(length)>110000))throw new Error("Request body exceeds the 110 KB limit.");
 if(!request.body)throw new Error("A JSON request body is required.");
 const reader=request.body.getReader();const chunks:Uint8Array[]=[];let total=0;
 try{while(true){const {done,value}=await reader.read();if(done)break;if(!value)continue;total+=value.byteLength;if(total>110000){await reader.cancel();throw new Error("Request body exceeds the 110 KB limit.");}chunks.push(value);}}
 finally{reader.releaseLock();}
 const bytes=new Uint8Array(total);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}
 try{return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes));}catch{throw new Error("Request body must be valid UTF-8 JSON.");}
}
export async function POST(request:Request){
 let body:unknown;try{body=await readBoundedBody(request);}catch(error){const message=error instanceof Error?error.message:"Invalid request.";return Response.json({error:message},{status:/limit/.test(message)?413:400});}
 if(!body||typeof body!=="object"||typeof (body as {source?:unknown}).source!=="string")return Response.json({error:"A Solidity source string is required."},{status:400});
 const source=(body as {source:string}).source;
 if(source.length>100000)return Response.json({error:"Solidity source exceeds the 100 KB limit."},{status:413});
 try{return Response.json({analysis:analyzeSoliditySource(source),sourceBytes:new TextEncoder().encode(source).byteLength},{headers:{"Cache-Control":"no-store"}});}
 catch(error){return Response.json({error:error instanceof Error?error.message:"Static analysis failed."},{status:400});}
}
