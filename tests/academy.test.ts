import { test } from "node:test";
import assert from "node:assert/strict";
import {
  normalizeAnswer, checkAnswer, trackProgress, gradeExam, certSerial, examForClient,
} from "../lib/academy";
import { TRACKS, findTrack, allTasks } from "../lib/academy-content";

test("answer normalization and checking", () => {
  assert.equal(normalizeAnswer("  X-Frame-Options  "), "x-frame-options");
  assert.equal(checkAnswer({ answer: "X-Frame-Options" }, "x-frame-options"), true);
  assert.equal(checkAnswer({ answer: "HSTS" }, "hsts"), true);
  assert.equal(checkAnswer({ answer: "HSTS" }, "wrong"), false);
  assert.equal(checkAnswer({ answer: undefined }, ""), true); // no-answer task
});

test("track progress rolls up tasks and rooms", () => {
  const track = findTrack("web-appsec")!;
  const tasks = allTasks(track);
  const empty = trackProgress(track, new Set());
  assert.equal(empty.completedTasks, 0);
  assert.equal(empty.percent, 0);
  assert.equal(empty.complete, false);
  const all = trackProgress(track, new Set(tasks.map((t) => t.id)));
  assert.equal(all.completedTasks, all.totalTasks);
  assert.equal(all.percent, 100);
  assert.equal(all.complete, true);
  assert.equal(all.completedRooms, all.totalRooms);
});

test("completing one full room counts as a completed room", () => {
  const track = findTrack("web-appsec")!;
  const firstRoom = track.rooms[0];
  const prog = trackProgress(track, new Set(firstRoom.tasks.map((t) => t.id)));
  assert.equal(prog.completedRooms, 1);
  assert.equal(prog.complete, false);
});

test("exam grading and pass threshold", () => {
  const cert = findTrack("web-appsec")!.certification!;
  const key: Record<string, string> = {};
  for (const q of cert.exam) key[q.id] = q.answer;
  const perfect = gradeExam(cert, key);
  assert.equal(perfect.percent, 100);
  assert.equal(perfect.passed, true);

  const twoWrong = { ...key };
  cert.exam.slice(0, 2).forEach((q) => { twoWrong[q.id] = "z"; });
  const failing = gradeExam(cert, twoWrong); // 3/5 = 60% < 80
  assert.equal(failing.correct, cert.exam.length - 2);
  assert.equal(failing.passed, false);
});

test("exam sent to client has no answer keys", () => {
  const cert = findTrack("web-appsec")!.certification!;
  const client = examForClient(cert);
  assert.equal(client.exam.length, cert.exam.length);
  for (const q of client.exam) assert.equal((q as Record<string, unknown>).answer, undefined);
});

test("certificate serial is readable", () => {
  assert.equal(certSerial("CCWT", "7f3a9c2d-1111"), "CCWT-7F3A9C2D");
});

test("every track with a certification has a non-empty exam and unique ids", () => {
  for (const track of TRACKS) {
    const ids = new Set(allTasks(track).map((t) => t.id));
    assert.equal(ids.size, allTasks(track).length, `duplicate task id in ${track.id}`);
    if (track.certification) assert.ok(track.certification.exam.length > 0);
  }
});
