import { NextRequest, NextResponse } from "next/server";
import { randomUUID } from "crypto";
import { requireUser, dbError } from "@/lib/social-auth";
import { gradeExam, trackProgress, certSerial } from "@/lib/academy";
import { findTrack } from "@/lib/academy-content";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const auth = await requireUser();
  if ("error" in auth) return auth.error;
  const { data, error } = await auth.supabase.from("academy_certificates")
    .select("track_id,code,serial,percent,issued_at").eq("owner", auth.user.id);
  if (error) return dbError(error.message);
  return NextResponse.json({ certificates: data ?? [] }, { headers: { "Cache-Control": "no-store" } });
}

export async function POST(request: NextRequest) {
  let body: unknown;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Expected JSON." }, { status: 400 }); }
  const v = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const trackId = typeof v.trackId === "string" ? v.trackId : "";
  const answers = (v.answers && typeof v.answers === "object" ? v.answers : {}) as Record<string, string>;

  const track = findTrack(trackId);
  if (!track || !track.certification) return NextResponse.json({ error: "No certification for this track." }, { status: 404 });

  const auth = await requireUser();
  if ("error" in auth) return auth.error;

  // The track's rooms must be fully completed before the exam counts.
  const { data: prog } = await auth.supabase.from("academy_progress").select("task_id").eq("owner", auth.user.id);
  const done = new Set((prog ?? []).map((r) => r.task_id));
  const progress = trackProgress(track, done);
  if (!progress.complete) {
    return NextResponse.json({ error: "Finish every room in the track before taking the exam.", progress }, { status: 400 });
  }

  const result = gradeExam(track.certification, answers);
  if (!result.passed) return NextResponse.json({ passed: false, result }, { status: 200 });

  // Idempotent: if already certified, return the existing certificate.
  const { data: existing } = await auth.supabase.from("academy_certificates")
    .select("track_id,code,serial,percent,issued_at").eq("owner", auth.user.id).eq("track_id", trackId).maybeSingle();
  if (existing) return NextResponse.json({ passed: true, result, certificate: existing });

  const serial = certSerial(track.certification.code, randomUUID());
  const row = { owner: auth.user.id, track_id: trackId, code: track.certification.code, serial, percent: result.percent };
  const { data, error } = await auth.supabase.from("academy_certificates")
    .insert(row).select("track_id,code,serial,percent,issued_at").single();
  if (error) return dbError(error.message);
  return NextResponse.json({ passed: true, result, certificate: data }, { status: 201 });
}
