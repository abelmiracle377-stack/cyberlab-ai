import { NextRequest, NextResponse } from "next/server";
import { requireUser, dbError } from "@/lib/social-auth";
import { checkAnswer } from "@/lib/academy";
import { findTask } from "@/lib/academy-content";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const auth = await requireUser();
  if ("error" in auth) return auth.error;
  const { data, error } = await auth.supabase.from("academy_progress")
    .select("task_id").eq("owner", auth.user.id).limit(2000);
  if (error) return dbError(error.message);
  return NextResponse.json({ completed: (data ?? []).map((r) => r.task_id) },
    { headers: { "Cache-Control": "no-store" } });
}

export async function POST(request: NextRequest) {
  let body: unknown;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Expected JSON." }, { status: 400 }); }
  const v = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const taskId = typeof v.taskId === "string" ? v.taskId : "";
  const answer = typeof v.answer === "string" ? v.answer : "";

  const task = findTask(taskId);
  if (!task) return NextResponse.json({ error: "Unknown task." }, { status: 404 });
  // Answers are graded server-side so the key never reaches the browser.
  if (!checkAnswer(task, answer)) {
    return NextResponse.json({ completed: false, error: "Incorrect — try again." }, { status: 200 });
  }
  const auth = await requireUser();
  if ("error" in auth) return auth.error;
  const { error } = await auth.supabase.from("academy_progress")
    .upsert({ owner: auth.user.id, task_id: taskId }, { onConflict: "owner,task_id" });
  if (error) return dbError(error.message);
  return NextResponse.json({ completed: true });
}
