import { NextResponse } from "next/server";
import { publicTracks } from "@/lib/academy-content";

export const runtime = "nodejs";

// Static curriculum with answer keys stripped; safe to serve to any client.
export async function GET() {
  return NextResponse.json({ tracks: publicTracks() },
    { headers: { "Cache-Control": "public, max-age=300" } });
}
