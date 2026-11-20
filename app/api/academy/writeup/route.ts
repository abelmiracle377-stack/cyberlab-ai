import { NextRequest, NextResponse } from "next/server";
import { requireUser, dbError } from "@/lib/social-auth";
import { findTask } from "@/lib/academy-content";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// A challenge write-up is a spoiler, so it is released only after the learner
// has captured that task's flag (recorded in academy_progress).
export async function GET(request: NextRequest) {
  const taskId = request.nextUrl.searchParams.get("taskId") || "";
  const task = findTask(taskId);
  if (!task) return NextResponse.json({ error: "Unknown task." }, { status: 404 });
  if (!task.writeup && !task.walkthroughUrl) return NextResponse.json({ error: "No write-up for this task." }, { status: 404 });

  const auth = await requireUser();
  if ("error" in auth) return auth.error;
  const { data, error } = await auth.supabase.from("academy_progress")
    .select("task_id").eq("owner", auth.user.id).eq("task_id", taskId).maybeSingle();
  if (error) return dbError(error.message);
  if (!data) return NextResponse.json({ error: "Capture this flag first to unlock the write-up." }, { status: 403 });

  return NextResponse.json({ writeup: task.writeup ?? "", walkthroughUrl: task.walkthroughUrl ?? "" },
    { headers: { "Cache-Control": "no-store" } });
}
