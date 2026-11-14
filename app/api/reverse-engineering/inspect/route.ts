import { createHash } from "node:crypto";
export const runtime="nodejs";
const MAX_BYTES=4*1024*1024;
function entropy(data:Buffer){if(!data.length)return 0;const counts=new Array<number>(256).fill(0);for(const b of data)counts[b]++;let e=0;for(const n of counts)if(n){const p=n/data.length;e-=p*Math.log2(p);}return Number(e.toFixed(3));}
function inspect(data:Buffer){
 if(data.length>=64&&data.toString("ascii",0,2)==="MZ"){
  const offset=data.readUInt32LE(60);
  if(offset+26<=data.length&&data.toString("ascii",offset,offset+4)==="PE\0\0"){
   const machine=data.readUInt16LE(offset+4),sections=data.readUInt16LE(offset+6),timestamp=data.readUInt32LE(offset+8),magic=data.readUInt16LE(offset+24);
   const arch:Record<number,string>={332:"x86",34404:"x86-64",43620:"ARM64",452:"ARM"};
   return {format:"PE",architecture:arch[machine]||"Unknown",machine:"0x"+machine.toString(16),sections,linkerTimestamp:timestamp?new Date(timestamp*1000).toISOString():"Not set",optionalHeader:magic===267?"PE32":magic===523?"PE32+":"Unknown"};
  }
  return {format:"MZ",detail:"PE signature not found at the expected header offset."};
 }
 if(data.length>=20&&data.toString("hex",0,4)==="7f454c46"){
  const cls=data[4],endian=data[5],little=endian===1;
  const u16=(offset:number)=>little?data.readUInt16LE(offset):data.readUInt16BE(offset);
  const type=u16(16),machine=u16(18);
  const arch:Record<number,string>={3:"x86",62:"x86-64",40:"ARM",183:"AArch64",243:"RISC-V"};
  const types:Record<number,string>={0:"ET_NONE",1:"ET_REL",2:"ET_EXEC",3:"ET_DYN",4:"ET_CORE"};
  return {format:"ELF",class:cls===1?"32-bit":cls===2?"64-bit":"Unknown",endianness:little?"Little-endian":endian===2?"Big-endian":"Unknown",architecture:arch[machine]||"Unknown",machine:"0x"+machine.toString(16),objectType:types[type]||"Unknown"};
 }
 const magic=data.toString("hex",0,4);
 const mach:Record<string,string>={"feedface":"Mach-O 32-bit big-endian","feedfacf":"Mach-O 64-bit big-endian","cefaedfe":"Mach-O 32-bit little-endian","cffaedfe":"Mach-O 64-bit little-endian"};
 if(mach[magic])return {format:"Mach-O",byteOrder:mach[magic],detail:"Header magic identified; load commands are not parsed by this starter."};
 return {format:"Unknown",detail:"No supported PE, ELF or Mach-O executable header was recognised."};
}
export async function POST(request:Request){
 let form:FormData;try{form=await request.formData();}catch{return Response.json({error:"Send a multipart file upload."},{status:400});}
 const file=form.get("file");if(!(file instanceof File))return Response.json({error:"Choose a binary file to inspect."},{status:400});
 if(file.size===0)return Response.json({error:"The selected file is empty."},{status:400});
 if(file.size>MAX_BYTES)return Response.json({error:"File exceeds the 4 MB limit."},{status:413});
 const data=Buffer.from(await file.arrayBuffer());
 return Response.json({fileName:file.name.slice(0,180),size:data.length,sha256:createHash("sha256").update(data).digest("hex"),entropy:entropy(data),metadata:inspect(data),note:"Static header inspection only. The file was not executed, unpacked, emulated or stored. Header fields can be missing or deliberately misleading."});
}
