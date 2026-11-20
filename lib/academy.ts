// Pure, dependency-free Academy logic: answer checking, progress, exam grading.
// Import-free so it compiles and unit-tests standalone (CI node --test).

import type { AcademyTrack, AcademyTask, Certification, CertQuestion } from "./academy-content";

export function normalizeAnswer(value: string): string {
  return String(value ?? "").trim().toLowerCase().replace(/\s+/g, " ");
}

// A task with no `answer` is completed by marking it done; a task with an
// `answer` requires a matching (normalised) flag/short answer.
export function checkAnswer(task: Pick<AcademyTask, "answer">, submitted: string): boolean {
  if (!task.answer) return true;
  return normalizeAnswer(task.answer) === normalizeAnswer(submitted);
}

export type TrackProgress = {
  completedTasks: number; totalTasks: number; percent: number;
  completedRooms: number; totalRooms: number; complete: boolean;
};

export function trackProgress(track: AcademyTrack, completed: Set<string>): TrackProgress {
  let total = 0, done = 0, roomsDone = 0;
  for (const room of track.rooms) {
    let roomTotal = 0, roomDone = 0;
    for (const task of room.tasks) {
      total += 1; roomTotal += 1;
      if (completed.has(task.id)) { done += 1; roomDone += 1; }
    }
    if (roomTotal > 0 && roomDone === roomTotal) roomsDone += 1;
  }
  return {
    completedTasks: done, totalTasks: total,
    percent: total ? Math.round((done / total) * 100) : 0,
    completedRooms: roomsDone, totalRooms: track.rooms.length,
    complete: total > 0 && done === total,
  };
}

export type ExamResult = { correct: number; total: number; percent: number; passed: boolean };

export function gradeExam(cert: Certification, answers: Record<string, string>): ExamResult {
  const total = cert.exam.length;
  let correct = 0;
  for (const q of cert.exam) if (answers[q.id] === q.answer) correct += 1;
  const percent = total ? Math.round((correct / total) * 100) : 0;
  return { correct, total, percent, passed: percent >= cert.passPercent };
}

// A stable, human-readable certificate serial, e.g. CCWT-7F3A9C2D.
export function certSerial(code: string, uniqueHex: string): string {
  return `${code}-${uniqueHex.replace(/[^a-fA-F0-9]/g, "").slice(0, 8).toUpperCase()}`;
}

// The exam is sent to the browser without the answer keys.
export function examForClient(cert: Certification): { code: string; title: string; passPercent: number; exam: Omit<CertQuestion, "answer">[] } {
  return {
    code: cert.code, title: cert.title, passPercent: cert.passPercent,
    exam: cert.exam.map(({ id, prompt, options }) => ({ id, prompt, options })),
  };
}
