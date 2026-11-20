// CyberLab Academy curriculum — Hack The Box / TryHackMe-style tracks.
//
// Content-driven: add tracks, rooms, tasks, videos and exams here without
// touching the engine or UI. Each task may carry an `answer` (a flag/short
// answer graded server-side) or be a read/do step completed by the learner.
// `videoUrl` is embedded when it is a YouTube watch/short link, otherwise shown
// as an "Open video" link; operators can point it at an uploaded video's URL
// (e.g. a Supabase Storage public URL) to host their own.

export type AcademyResource = { title: string; url: string };
export type AcademyTask = {
  id: string; title: string; instructions: string;
  answer?: string; hint?: string; videoUrl?: string;
};
export type AcademyRoom = {
  id: string; title: string; summary: string;
  difficulty: "intro" | "easy" | "medium" | "hard";
  tool?: string; toolHref?: string; videoUrl?: string;
  resources?: AcademyResource[]; tasks: AcademyTask[];
};
export type CertQuestion = { id: string; prompt: string; options: { id: string; text: string }[]; answer: string };
export type Certification = { code: string; title: string; passPercent: number; exam: CertQuestion[] };
export type AcademyTrack = {
  id: string; title: string; summary: string;
  level: "beginner" | "intermediate" | "advanced";
  rooms: AcademyRoom[]; certification?: Certification;
};

export const TRACKS: AcademyTrack[] = [
  {
    id: "web-appsec",
    title: "Web Application Security",
    summary: "Learn to find real web bugs the way a bug-bounty hunter does, using CyberLab's own assessment engine on authorised targets.",
    level: "beginner",
    rooms: [
      {
        id: "http-headers",
        title: "HTTP & Security Headers",
        summary: "How HTTP requests and responses work, and the response headers that defend a site.",
        difficulty: "intro",
        tool: "Web Application Assessment", toolHref: "/web-assessment",
        videoUrl: "https://www.youtube.com/@PortSwiggerTV",
        resources: [
          { title: "OWASP Secure Headers Project", url: "https://owasp.org/www-project-secure-headers/" },
          { title: "MDN: HTTP headers", url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers" },
        ],
        tasks: [
          { id: "http-headers-1", title: "Request & response basics",
            instructions: "Read how a browser sends a request and the server replies with a status line, headers and a body. Then continue.",
            videoUrl: "https://www.youtube.com/@PortSwiggerTV" },
          { id: "http-headers-2", title: "Clickjacking defence",
            instructions: "Which response header, set to DENY or SAMEORIGIN, stops a page being framed by another site? Answer with the header name.",
            answer: "X-Frame-Options", hint: "It starts with X-Frame-…" },
          { id: "http-headers-3", title: "Force HTTPS",
            instructions: "Which header tells browsers to only ever use HTTPS for a site? Answer with the short abbreviation (4 letters).",
            answer: "HSTS", hint: "HTTP Strict Transport Security." },
          { id: "http-headers-4", title: "Run the assessment",
            instructions: "Open Web Application Assessment, point it at an origin you are authorised to test, and read which headers it flags as missing. Mark complete when done." },
        ],
      },
      {
        id: "info-disclosure",
        title: "Information & File Disclosure",
        summary: "Find secrets a site leaks by accident — source control, environment files and server status pages.",
        difficulty: "easy",
        tool: "Web Application Assessment", toolHref: "/web-assessment",
        resources: [
          { title: "OWASP WSTG: Review Webserver Metafiles", url: "https://owasp.org/www-project-web-security-testing-guide/" },
        ],
        tasks: [
          { id: "info-disclosure-1", title: "The exposed repository",
            instructions: "A web root sometimes serves its version-control folder. Which hidden folder, if downloadable, leaks a site's full source and history? Answer with the folder name (including the dot).",
            answer: ".git", hint: "Version control by Linus Torvalds." },
          { id: "info-disclosure-2", title: "Leaked secrets file",
            instructions: "Which dotfile commonly holds KEY=VALUE application secrets and must never be web-served? Answer with the filename.",
            answer: ".env" },
          { id: "info-disclosure-3", title: "Hunt with CyberLab",
            instructions: "Run the assessment against an authorised target and review the sensitive-path checks in the log. Mark complete when done." },
        ],
      },
      {
        id: "injection-xss",
        title: "Reflected Input & XSS",
        summary: "Understand how unescaped input becomes cross-site scripting, and how CyberLab detects reflection.",
        difficulty: "medium",
        tool: "Web Application Assessment", toolHref: "/web-assessment",
        videoUrl: "https://www.youtube.com/@PortSwiggerTV",
        resources: [
          { title: "PortSwigger: Cross-site scripting", url: "https://portswigger.net/web-security/cross-site-scripting" },
          { title: "OWASP XSS Prevention Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
        ],
        tasks: [
          { id: "injection-xss-1", title: "What is reflection?",
            instructions: "Read how a parameter value echoed into the page unescaped lets an attacker inject HTML or script. Then continue." },
          { id: "injection-xss-2", title: "The vulnerability class",
            instructions: "What three-letter acronym names the bug where attacker-controlled script runs in another user's browser? Answer with the acronym.",
            answer: "XSS" },
          { id: "injection-xss-3", title: "Detect, don't exploit",
            instructions: "CyberLab's engine reports reflected markers as candidates, never executing script. Explain to yourself why detection-only is the right default, then mark complete." },
        ],
      },
      {
        id: "sqli",
        title: "SQL Injection Fundamentals",
        summary: "How untrusted input reaches a database query, and the error signatures that reveal it.",
        difficulty: "medium",
        tool: "Web Application Assessment", toolHref: "/web-assessment",
        videoUrl: "https://www.youtube.com/@PortSwiggerTV",
        resources: [
          { title: "PortSwigger: SQL injection", url: "https://portswigger.net/web-security/sql-injection" },
          { title: "OWASP SQL Injection Prevention Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" },
        ],
        tasks: [
          { id: "sqli-1", title: "Breaking the query",
            instructions: "Which single character, appended to a parameter, most often breaks SQL string context and triggers a database error? Answer with the one character.",
            answer: "'", hint: "A single quote." },
          { id: "sqli-2", title: "The real fix",
            instructions: "What query technique — binding inputs as data, not string-concatenated SQL — prevents injection? Two words.",
            answer: "parameterized queries", hint: "Also called prepared statements." },
          { id: "sqli-3", title: "Detect error-based SQLi",
            instructions: "Run the assessment against an authorised target with a query parameter and review the SQL-error probe in the log. Mark complete when done." },
        ],
      },
    ],
    certification: {
      code: "CCWT", title: "CyberLab Certified Web Tester", passPercent: 80,
      exam: [
        { id: "ccwt-1", prompt: "Which header prevents clickjacking?",
          options: [{ id: "a", text: "X-Frame-Options" }, { id: "b", text: "Accept-Encoding" }, { id: "c", text: "ETag" }, { id: "d", text: "Cache-Control" }], answer: "a" },
        { id: "ccwt-2", prompt: "A publicly served /.git/HEAD most likely means:",
          options: [{ id: "a", text: "The site is secure" }, { id: "b", text: "Source code and history may be downloadable" }, { id: "c", text: "The server is offline" }, { id: "d", text: "HTTPS is enforced" }], answer: "b" },
        { id: "ccwt-3", prompt: "The correct defence against SQL injection is:",
          options: [{ id: "a", text: "Hiding error messages only" }, { id: "b", text: "Blocklisting quotes" }, { id: "c", text: "Parameterised queries / prepared statements" }, { id: "d", text: "A faster database" }], answer: "c" },
        { id: "ccwt-4", prompt: "CyberLab's assessment engine is:",
          options: [{ id: "a", text: "An exploitation framework" }, { id: "b", text: "Detection-only, within a confirmed authorised scope" }, { id: "c", text: "A DDoS tool" }, { id: "d", text: "A password cracker" }], answer: "b" },
        { id: "ccwt-5", prompt: "A missing SameSite cookie attribute primarily raises exposure to:",
          options: [{ id: "a", text: "CSRF" }, { id: "b", text: "Buffer overflow" }, { id: "c", text: "DNS spoofing" }, { id: "d", text: "Ransomware" }], answer: "a" },
      ],
    },
  },
  {
    id: "soc-analyst",
    title: "SOC Analyst Fundamentals",
    summary: "Triage alerts, read MITRE ATT&CK, and correlate incidents using CyberLab's CyberSOC — the skills of a blue-team analyst.",
    level: "beginner",
    rooms: [
      {
        id: "triage",
        title: "Alert Triage & Severity",
        summary: "Turn raw events into ranked alerts and decide what matters first.",
        difficulty: "intro",
        tool: "CyberSOC", toolHref: "/soc",
        resources: [{ title: "MITRE ATT&CK", url: "https://attack.mitre.org/" }],
        tasks: [
          { id: "triage-1", title: "What is triage?",
            instructions: "Read how an analyst ranks alerts by severity and score so the worst gets worked first. Then continue." },
          { id: "triage-2", title: "Highest severity",
            instructions: "In CyberLab's severity scale (informational, low, medium, high, critical), which is the most severe? Answer with the word.",
            answer: "critical" },
        ],
      },
      {
        id: "mitre",
        title: "MITRE ATT&CK & Correlation",
        summary: "Map activity to attacker tactics, and group related alerts into one incident.",
        difficulty: "easy",
        tool: "CyberSOC", toolHref: "/soc",
        resources: [{ title: "MITRE ATT&CK Tactics", url: "https://attack.mitre.org/tactics/enterprise/" }],
        tasks: [
          { id: "mitre-1", title: "Tactic vs technique",
            instructions: "ATT&CK organises attacker behaviour into tactics (the why) and techniques (the how). Read a few techniques, then continue." },
          { id: "mitre-2", title: "What correlation does",
            instructions: "CyberSOC groups alerts that share which three entity types into one incident? Answer with any one of them (host, source IP or user).",
            answer: "host", hint: "Also accepts src_ip or user — enter 'host'." },
          { id: "mitre-3", title: "Open a case",
            instructions: "In CyberSOC, open a case from an incident and read its consolidated timeline. Mark complete when done." },
        ],
      },
    ],
    certification: {
      code: "CCSA", title: "CyberLab Certified SOC Analyst", passPercent: 80,
      exam: [
        { id: "ccsa-1", prompt: "Which is the most severe alert level?",
          options: [{ id: "a", text: "medium" }, { id: "b", text: "high" }, { id: "c", text: "critical" }, { id: "d", text: "low" }], answer: "c" },
        { id: "ccsa-2", prompt: "MITRE ATT&CK tactics describe:",
          options: [{ id: "a", text: "The attacker's objective at each stage" }, { id: "b", text: "Firewall rules" }, { id: "c", text: "TLS ciphers" }, { id: "d", text: "Database schemas" }], answer: "a" },
        { id: "ccsa-3", prompt: "CyberSOC correlates alerts into an incident when they share:",
          options: [{ id: "a", text: "The same colour" }, { id: "b", text: "A host, source IP or user" }, { id: "c", text: "Nothing" }, { id: "d", text: "The same timestamp only" }], answer: "b" },
        { id: "ccsa-4", prompt: "A case in CyberSOC is:",
          options: [{ id: "a", text: "A single alert" }, { id: "b", text: "An investigation spanning several alerts with a shared timeline" }, { id: "c", text: "A firewall" }, { id: "d", text: "A password vault" }], answer: "b" },
        { id: "ccsa-5", prompt: "Mean Time To Resolve (MTTR) measures:",
          options: [{ id: "a", text: "Average time to close/resolve alerts" }, { id: "b", text: "Number of alerts" }, { id: "c", text: "CPU usage" }, { id: "d", text: "Disk space" }], answer: "a" },
      ],
    },
  },
];

export function findTrack(id: string): AcademyTrack | undefined {
  return TRACKS.find((t) => t.id === id);
}
export function allTasks(track: AcademyTrack): AcademyTask[] {
  return track.rooms.flatMap((r) => r.tasks);
}
export function findTask(taskId: string): AcademyTask | undefined {
  for (const track of TRACKS) {
    const task = allTasks(track).find((t) => t.id === taskId);
    if (task) return task;
  }
  return undefined;
}

// Content shaped for the browser: `answer` keys are stripped and replaced with a
// `requiresAnswer` flag, and exam options carry no answer. Grading stays server-side.
export function publicTracks() {
  return TRACKS.map((t) => ({
    id: t.id, title: t.title, summary: t.summary, level: t.level,
    rooms: t.rooms.map((r) => ({
      id: r.id, title: r.title, summary: r.summary, difficulty: r.difficulty,
      tool: r.tool, toolHref: r.toolHref, videoUrl: r.videoUrl, resources: r.resources,
      tasks: r.tasks.map((task) => ({
        id: task.id, title: task.title, instructions: task.instructions,
        hint: task.hint, videoUrl: task.videoUrl, requiresAnswer: Boolean(task.answer),
      })),
    })),
    certification: t.certification ? {
      code: t.certification.code, title: t.certification.title, passPercent: t.certification.passPercent,
      exam: t.certification.exam.map(({ id, prompt, options }) => ({ id, prompt, options })),
    } : null,
  }));
}
