# CyberLab Academy — Hack The Box / TryHackMe-style learning

The Academy teaches real offensive and defensive skills on CyberLab's own
tools, in hands-on **rooms** grouped into **tracks**, with videos, flag answers
and earnable **certifications**.

## Structure

- **Track** → a learning path (e.g. *Web Application Security*, *SOC Analyst
  Fundamentals*) with a `level` and an optional certification.
- **Room** → a lesson with a difficulty (`intro`→`hard`), an optional linked
  CyberLab tool, a video, reading resources, and a list of tasks.
- **Task** → a step. Either a read/do step (completed with "Mark complete") or a
  **flag task** with a short answer graded server-side.
- **Certification** → unlocked once every room in the track is complete; a
  multiple-choice exam graded server-side issues a certificate with a unique,
  human-readable serial (e.g. `CCWT-7F3A9C2D`) once the pass mark is met.

Content lives in `lib/academy-content.ts` — add tracks, rooms, tasks, videos and
exams there; no engine or UI change is needed. Pure logic (answer checking,
progress roll-up, exam grading, serials) is in `lib/academy.ts`, unit-tested in
`tests/academy.test.ts`.

## Videos

Each room or task may carry a `videoUrl`:

- A YouTube **watch**, **youtu.be** or **shorts** link is embedded inline in the
  room as a player.
- Any other link (a channel, playlist, or a page) renders as an "Open video"
  link.
- To **host your own uploaded video**, upload it to a Supabase Storage bucket
  (e.g. `academy-videos`, public read) and set the task's `videoUrl` to the
  file's public URL, or set it to a direct `.mp4`/`.webm` URL.

## Hands-on CTF lab (bundled vulnerable target)

The *Capture The Flag: Vulnerable Shop* track runs against a real, deliberately
vulnerable web app bundled with the companion (`kali-companion/academy_lab.py`).
It binds **127.0.0.1 only** — a sandbox on the learner's own machine, nothing
external. The "The Vulnerable Shop" room has a **Start lab** button that calls
the paired companion (`POST /academy/lab/start`); the learner then attacks the
target with the assessment tool, a browser or a repeater and submits the five
flags they capture:

- `/robots.txt` recon → a disallowed hidden path reveals a flag
- `/.env` file disclosure
- `/.git/config` source disclosure
- an `X-Flag` response header on `/api/status`
- error-based SQL injection on `/product?id=1'`

Flags are fixed and matched by the track's task answers (stripped from the
browser), so a learner must actually perform the technique to capture them.
`build_response` is a pure function, unit-tested in `test_academy_lab.py`.
Bridge routes: `POST /academy/lab/start`, `POST /academy/lab/stop`,
`GET /academy/lab/status`.

## Public certificate verification

`/verify` confirms a certificate by serial for anyone — no login needed — via a
`SECURITY DEFINER` function `verify_certificate(serial)` that returns only the
public fields (code, track, score, issue date, serial), never the owner. Apply
`supabase/migrations/202611200008_academy_verify.sql`. Earned certificates on
the Academy home link to `/verify?serial=…`.

## Answer integrity

The browser is served curriculum with answer keys stripped
(`publicTracks()` / `GET /api/academy/content`). Flag answers and exam keys stay
server-side: `POST /api/academy/progress` grades a flag, and
`POST /api/academy/certificate` grades the exam and issues the certificate.

## Data & API

Apply `supabase/migrations/202611200007_academy.sql` after the earlier
migrations. It creates:

- `academy_progress` — one row per completed task (`unique(owner, task_id)`).
- `academy_certificates` — issued certificates (`unique(owner, track_id)`,
  unique `serial`).

Both are owner-scoped with Row-Level Security.

Routes:

- `GET /api/academy/content` — curriculum (answer keys stripped).
- `GET/POST /api/academy/progress` — list completed tasks / submit a task or flag.
- `GET/POST /api/academy/certificate` — list issued certs / take the exam.

## UI

`/academy` (sidebar → **LEARN → Academy**): browse tracks with progress bars,
drill into a room to watch its video, read resources, work tasks and submit
flags, then take the certification exam when the track is complete. Earned
certificates show their serial on the track and the Academy home.
