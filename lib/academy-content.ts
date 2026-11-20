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
  // Spoiler content — revealed only after the learner captures this task's flag.
  writeup?: string; walkthroughUrl?: string;
};
export type AcademyRoom = {
  id: string; title: string; summary: string;
  difficulty: "intro" | "easy" | "medium" | "hard";
  tool?: string; toolHref?: string; videoUrl?: string;
  lab?: boolean; resources?: AcademyResource[]; tasks: AcademyTask[];
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

// Capture-the-flag track against the bundled vulnerable lab (academy_lab.py).
// Answers MUST match the lab's flags exactly.
TRACKS.push({
  id: "ctf-lab",
  title: "Capture The Flag: Vulnerable Shop",
  summary: "Attack a bundled, deliberately vulnerable target that runs on your own machine (loopback only) and capture real flags — the hands-on way to practise everything the Web track teaches.",
  level: "intermediate",
  rooms: [
    {
      id: "ctf-tier1",
      title: "Tier 1 — Recon & Disclosure",
      summary: "Start the lab here, then capture four flags through recon and accidental file/header disclosure.",
      difficulty: "easy",
      tool: "Web Application Assessment", toolHref: "/web-assessment",
      lab: true,
      resources: [{ title: "OWASP WSTG", url: "https://owasp.org/www-project-web-security-testing-guide/" }],
      tasks: [
        { id: "ctf-recon", title: "Robots recon",
          instructions: "Start the lab (button above). Request /robots.txt on the lab's base URL, follow the Disallowed path, and submit the flag it returns.",
          answer: "CYBERLAB{recon_robots_txt}", hint: "Disallow: points at a hidden path.",
          walkthroughUrl: "https://owasp.org/www-project-web-security-testing-guide/",
          writeup: "robots.txt tells crawlers which paths to avoid — which means it often advertises exactly the sensitive paths a developer wanted hidden. It is one of the first files a tester requests. Here, the Disallow entry points at /flag-7a1c; visiting it returns the flag. The lesson: 'security through obscurity' isn't security. A path is not protected just because it isn't linked. Fix: never list sensitive locations in robots.txt, and protect them with real authentication and authorization instead." },
        { id: "ctf-dotenv", title: "Exposed .env",
          instructions: "The app serves its environment file. Request /.env and submit the FLAG= value.",
          answer: "CYBERLAB{dotenv_secrets_exposed}",
          walkthroughUrl: "https://owasp.org/www-project-web-security-testing-guide/",
          writeup: "A .env file holds an app's configuration secrets — database passwords, API keys, signing keys. It belongs outside the web root, but a misconfigured server (or a deploy that copied it into the public folder) serves it like any other file. Requesting /.env returns KEY=VALUE lines, here including the flag. In the real world this is a full compromise: the leaked DB password or API key is immediately usable. Fix: keep .env out of the document root, block dotfiles at the web server, and rotate any secret that was ever exposed." },
        { id: "ctf-git", title: "Exposed .git",
          instructions: "The version-control folder is downloadable. Read /.git/config and submit the flag in its comment.",
          answer: "CYBERLAB{git_source_leak}", hint: "Also try /.git/HEAD to confirm the exposure.",
          walkthroughUrl: "https://owasp.org/www-project-web-security-testing-guide/",
          writeup: "When a site is deployed by copying a git working tree, the hidden .git/ folder often ships too. Because the server lists it like any directory, an attacker can download the whole repository — full source code and commit history — with tools like git-dumper. /.git/HEAD returning 'ref: refs/heads/main' confirms the exposure; /.git/config here carries the flag. The impact is total source disclosure, which often includes hard-coded secrets in old commits. Fix: deploy build artifacts rather than the git tree, and deny access to /.git at the web server." },
        { id: "ctf-header", title: "Leaky response header",
          instructions: "Inspect the response headers of /api/status (use the assessment tool or a repeater). Submit the value of the X-Flag header.",
          answer: "CYBERLAB{response_header_leak}",
          walkthroughUrl: "https://owasp.org/www-project-secure-headers/",
          writeup: "The body of a response is only half of it — the headers carry just as much. Debug builds, proxies and frameworks frequently leak internal data in custom headers (X-Debug, X-Powered-By, verbose Server strings). Here /api/status returns an X-Flag header that the page body never shows, so you only find it by inspecting the raw response. Always read headers in a repeater or the assessment tool, not just the rendered page. Fix: strip debug and technology-disclosure headers in production." },
      ],
    },
    {
      id: "ctf-tier2",
      title: "Tier 2 — Injection & Broken Access",
      summary: "Error-based SQLi, an IDOR on another user's order, and a path traversal to a secret file.",
      difficulty: "medium",
      tool: "Web Application Assessment", toolHref: "/web-assessment",
      lab: true,
      tasks: [
        { id: "ctf-sqli", title: "Error-based SQL injection",
          instructions: "Break the product query: request /product?id=1' (a single quote). The database error leaks a debug flag. Submit it.",
          answer: "CYBERLAB{error_based_sqli}", hint: "A single quote breaks SQL string context.",
          walkthroughUrl: "https://portswigger.net/web-security/sql-injection",
          writeup: "When user input is concatenated straight into a SQL query, a single quote breaks out of the string literal and corrupts the query's syntax. A server that returns the raw database error (error-based SQLi) confirms the injection point and often leaks schema detail — here, a debug flag. Real exploitation would move on to UNION or boolean/blind techniques to read arbitrary data. CyberLab's engine only detects the error signature; it never extracts data. Fix: use parameterised queries / prepared statements so input is always bound as data, never parsed as SQL, and return generic error pages." },
        { id: "ctf-idor", title: "IDOR on orders",
          instructions: "Your order is /api/orders?id=1001. Change the id to read another user's order and submit the flag it contains.",
          answer: "CYBERLAB{idor_order_access}", hint: "Try the id just below yours.",
          walkthroughUrl: "https://portswigger.net/web-security/access-control/idor",
          writeup: "An Insecure Direct Object Reference is broken access control: the app looks up an object by an id you supply, but never checks that the object belongs to you. Your order is 1001; changing the id to 1000 returns another user's order — and the flag. IDOR is one of the most common and highest-impact real-world bugs because it exposes other users' data at scale, just by incrementing a number. Fix: enforce an authorization check on every object access (does this user own this record?), and prefer unguessable identifiers as defence in depth, never as the only control." },
        { id: "ctf-traversal", title: "Path traversal",
          instructions: "The /download?file= endpoint reads a file by name. Traverse up the directories to reach the secret flag file and submit the flag.",
          answer: "CYBERLAB{path_traversal_secret}", hint: "../../ … /flag.txt",
          walkthroughUrl: "https://portswigger.net/web-security/file-path-traversal",
          writeup: "Path (directory) traversal happens when an app builds a filesystem path from user input without constraining it. Sequences like ../ climb out of the intended directory, letting you read files the app never meant to serve — classically /etc/passwd, or here a secret flag file. The impact is arbitrary file read: source code, config, keys. Fix: resolve the path and verify it stays within an allow-listed base directory, reject any input containing path separators or '..', and prefer mapping an opaque id to a known file rather than taking a filename at all." },
      ],
    },
    {
      id: "ctf-tier3",
      title: "Tier 3 — Auth & Advanced",
      summary: "Forge a role cookie, bypass JWT verification with alg:none, and reach an internal service via SSRF.",
      difficulty: "hard",
      tool: "Web Application Assessment", toolHref: "/web-assessment",
      lab: true,
      resources: [
        { title: "PortSwigger: JWT attacks", url: "https://portswigger.net/web-security/jwt" },
        { title: "PortSwigger: SSRF", url: "https://portswigger.net/web-security/ssrf" },
      ],
      tasks: [
        { id: "ctf-authbypass", title: "Cookie auth bypass",
          instructions: "/admin trusts a client-set role. Send a request with the header Cookie: role=admin (use a repeater or the browser dev tools) and submit the flag.",
          answer: "CYBERLAB{cookie_role_forgery}",
          walkthroughUrl: "https://portswigger.net/web-security/access-control",
          writeup: "This is broken access control via a trusted client value. The app decides who is an admin by reading a role=... cookie — but cookies are fully attacker-controlled. Setting Cookie: role=admin grants the admin area and the flag. Anything the client can set (cookies, hidden fields, headers) must be treated as untrusted. Fix: derive privileges from a server-side session tied to an authenticated identity, sign/encrypt session state, and check authorization on the server for every privileged action — never from a client-supplied role flag." },
        { id: "ctf-jwt", title: "JWT alg:none",
          instructions: "/api/profile accepts an unsigned token. Craft a JWT with header {\"alg\":\"none\"} and payload {\"role\":\"admin\"} (base64url, trailing dot, no signature) and send it as Authorization: Bearer <token>. Submit the flag.",
          answer: "CYBERLAB{jwt_alg_none}", hint: "No signature needed when the server trusts alg:none.",
          walkthroughUrl: "https://portswigger.net/web-security/jwt",
          writeup: "A JWT is header.payload.signature; the header's 'alg' field says how it was signed. The spec allows alg 'none' (an unsigned token), and libraries that honour it will accept a token with no signature at all. So you forge one: set the header to {\"alg\":\"none\"} and the payload to {\"role\":\"admin\"}, base64url-encode both, and send header.payload. with an empty signature and the trailing dot. The server trusts it and returns the flag. Fix: never accept alg 'none', pin the expected algorithm server-side, and always verify the signature with the correct key — use verify(), not decode()." },
        { id: "ctf-ssrf", title: "SSRF to internal metadata",
          instructions: "/fetch?url= will request a URL you give it. Point it at the internal metadata address 169.254.169.254 and submit the flag it returns.",
          answer: "CYBERLAB{ssrf_internal_metadata}",
          walkthroughUrl: "https://portswigger.net/web-security/ssrf",
          writeup: "Server-Side Request Forgery tricks the server into making a request on your behalf. Because that request originates from inside the network, it can reach things you can't — internal admin panels, databases, and cloud metadata services. The classic target is 169.254.169.254, the link-local metadata endpoint on AWS/GCP/Azure, which can hand out temporary cloud credentials. Here, pointing /fetch?url= at it returns the flag. (CyberLab's lab recognises the internal target and returns the lesson flag; it never makes a real request.) Fix: allow-list permitted destinations, block link-local/private ranges and redirects, and require IMDSv2 / disable metadata where possible." },
      ],
    },
  ],
  certification: {
    code: "CCCP", title: "CyberLab Certified CTF Player", passPercent: 80,
    exam: [
      { id: "cccp-1", prompt: "Where does robots.txt help an attacker?",
        options: [{ id: "a", text: "It encrypts traffic" }, { id: "b", text: "It can disclose hidden paths" }, { id: "c", text: "It blocks all bots" }, { id: "d", text: "It patches the server" }], answer: "b" },
      { id: "cccp-2", prompt: "A web-served .env file is dangerous because it:",
        options: [{ id: "a", text: "Speeds up the site" }, { id: "b", text: "Leaks application secrets" }, { id: "c", text: "Is required by HTTP" }, { id: "d", text: "Is always empty" }], answer: "b" },
      { id: "cccp-3", prompt: "Error-based SQL injection is revealed by:",
        options: [{ id: "a", text: "A 404 page" }, { id: "b", text: "A database error after breaking query syntax" }, { id: "c", text: "A redirect" }, { id: "d", text: "A favicon" }], answer: "b" },
      { id: "cccp-4", prompt: "Inspecting response headers can reveal:",
        options: [{ id: "a", text: "Nothing useful" }, { id: "b", text: "Debug values and technology disclosure" }, { id: "c", text: "The user's password" }, { id: "d", text: "The server's CPU" }], answer: "b" },
      { id: "cccp-5", prompt: "The lab target runs:",
        options: [{ id: "a", text: "On the public internet" }, { id: "b", text: "On loopback (127.0.0.1) on your own machine" }, { id: "c", text: "On a classmate's server" }, { id: "d", text: "In the cloud" }], answer: "b" },
    ],
  },
});

// Attack techniques explained for defenders — how each works, its impact, and
// how to stop it. Concepts and defences, not working attack payloads.
TRACKS.push({
  id: "attack-defense",
  title: "Attack Techniques & Defense",
  summary: "Understand how common attacks work and, more importantly, how to detect and prevent them — Cross-Site Scripting and SSH key security.",
  level: "intermediate",
  rooms: [
    {
      id: "xss",
      title: "Cross-Site Scripting (XSS)",
      summary: "How attacker-controlled script ends up running in another user's browser — and the layered defences that stop it.",
      difficulty: "medium",
      tool: "Web Application Assessment", toolHref: "/web-assessment",
      videoUrl: "https://www.youtube.com/@PortSwiggerTV",
      resources: [
        { title: "PortSwigger: Cross-site scripting", url: "https://portswigger.net/web-security/cross-site-scripting" },
        { title: "OWASP XSS Prevention Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
      ],
      tasks: [
        { id: "xss-types", title: "The three kinds of XSS",
          instructions: "Read how XSS splits into reflected (echoed from the request), stored (saved and served to others) and DOM-based (client-side sink). Then continue.",
          writeup: "XSS is an injection flaw where untrusted input is placed into a page without being neutralised, so the browser executes it as code. Reflected XSS bounces a value straight back from the request into the response; stored XSS is persisted (a comment, a profile field) and runs for every viewer, making it the most dangerous; DOM-based XSS never touches the server — client-side JavaScript writes attacker input into a dangerous sink like innerHTML or document.write. All three share one root cause: mixing data and code. The fix is to keep them apart at every layer.",
          walkthroughUrl: "https://portswigger.net/web-security/cross-site-scripting" },
        { id: "xss-acronym", title: "Name the vulnerability class",
          instructions: "What three-letter acronym names the bug where attacker-controlled script runs in another user's browser? Answer with the acronym.",
          answer: "XSS",
          writeup: "XSS = Cross-Site Scripting. The historical 'X' avoided confusion with CSS (stylesheets). Its impact is whatever the victim's session can do: reading or exfiltrating data on the page, performing actions as the user, capturing keystrokes, or stealing a session cookie to hijack the account. Because the script runs with the victim's privileges in their origin, XSS effectively defeats the same-origin policy for that page.",
          walkthroughUrl: "https://owasp.org/www-community/attacks/xss/" },
        { id: "xss-httponly", title: "Protecting the session cookie",
          instructions: "Which cookie flag stops client-side JavaScript from reading the cookie (so XSS can't steal the session via document.cookie)? Answer with the flag name.",
          answer: "HttpOnly", hint: "It makes the cookie invisible to document.cookie.",
          writeup: "The HttpOnly flag tells the browser not to expose a cookie to JavaScript, so even if XSS runs, document.cookie won't reveal the session token — closing the classic cookie-theft path. It is defence in depth, not a cure: an attacker can still act through the authenticated page itself. Pair it with Secure (HTTPS-only) and SameSite (cross-site request limits). Note the historical XST (Cross-Site Tracing) trick that abused the HTTP TRACE method to read HttpOnly cookies — which is why you also disable TRACE on servers; modern browsers already block it.",
          walkthroughUrl: "https://owasp.org/www-community/HttpOnly" },
        { id: "xss-csp", title: "Stopping inline script execution",
          instructions: "Which response header lets you block inline scripts and restrict where scripts may load from, neutralising most XSS? Answer with the header name.",
          answer: "Content-Security-Policy", hint: "Abbreviated CSP.",
          writeup: "A Content-Security-Policy (CSP) controls which script sources the browser will execute. A policy without 'unsafe-inline' refuses inline <script> and on* handlers, so an injected payload simply doesn't run — turning many XSS findings from critical into inert. CSP is the strongest single mitigation, but it sits on top of, not instead of, the real fix: context-aware output encoding (HTML, attribute, JS, URL) and input validation, plus safe DOM APIs (textContent, not innerHTML) and frameworks that auto-escape. Defence in depth: encode output, add CSP, set HttpOnly/Secure/SameSite, and validate input.",
          walkthroughUrl: "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html" },
      ],
    },
    {
      id: "ssh-security",
      title: "SSH Security & Key Hygiene",
      summary: "How SSH keys, agents and trust get abused — and the configuration that keeps them safe.",
      difficulty: "medium",
      resources: [
        { title: "SSH Academy", url: "https://www.ssh.com/academy/ssh" },
        { title: "CVE-2024-31497 (PuTTY)", url: "https://nvd.nist.gov/vuln/detail/CVE-2024-31497" },
      ],
      tasks: [
        { id: "ssh-perms", title: "Private key permissions",
          instructions: "What octal file mode should a private key (e.g. id_ed25519) have so only its owner can read it? Answer with the three-digit number.",
          answer: "600", hint: "Owner read/write only.",
          writeup: "A private key readable by other users is a handover of your identity. Keys should be 600 (owner read/write only), and ~/.ssh 700; OpenSSH refuses to use an over-permissive key for exactly this reason. Loose permissions are a common lateral-movement foothold: an attacker with a shell simply copies a world-readable id_rsa and authenticates as its owner. Audit for stray keys, store them encrypted with a passphrase, and keep them off shared hosts.",
          walkthroughUrl: "https://www.ssh.com/academy/ssh/keygen" },
        { id: "ssh-agent", title: "Agent forwarding risk",
          instructions: "Read why 'ForwardAgent yes' is risky: it exposes a socket on the remote host that anyone with root there can use to authenticate as you, without ever seeing the key. Then continue.",
          writeup: "SSH agent forwarding lets a remote host use your local agent to authenticate onward — convenient, but it places a live socket (SSH_AUTH_SOCK) on that host. Anyone with root on the intermediate box can use that socket to impersonate you to any system your keys unlock, for as long as your session lasts. Prefer ProxyJump (ssh -J) which never exposes the agent, set 'AllowAgentForwarding no' on servers you don't fully trust, scope keys per environment, and use 'ssh-add -c' to require confirmation on each use.",
          walkthroughUrl: "https://www.ssh.com/academy/ssh/agent" },
        { id: "ssh-authorized-keys", title: "authorized_keys persistence",
          instructions: "A common persistence trick is appending an attacker key to a victim's ~/.ssh/authorized_keys. What filename holds the public keys permitted to log into an account? Answer with the filename.",
          answer: "authorized_keys",
          writeup: "~/.ssh/authorized_keys lists the public keys allowed to log in as that user. Write access to it — via a misconfiguration, a web shell, or a weak account — lets an attacker append their own key for durable, password-less access that survives password changes. Defenders: monitor authorized_keys for unexpected entries (file-integrity monitoring), restrict who can write to home directories, consider centrally-managed keys or certificates (ssh-keygen CA) instead of per-user files, and alert on new public keys.",
          walkthroughUrl: "https://www.ssh.com/academy/ssh/authorized-keys-file" },
        { id: "ssh-keytype", title: "The key type to prefer",
          instructions: "Which modern SSH key type should you prefer over RSA/ECDSA for new keys (and which avoids the PuTTY CVE-2024-31497 P-521 nonce flaw)? Answer with the key type.",
          answer: "Ed25519", hint: "An EdDSA curve, not NIST P-521.",
          writeup: "Ed25519 is a fast, modern signature scheme with deterministic nonces, which sidesteps the biased-nonce class of bugs. CVE-2024-31497 affected PuTTY 0.68–0.80 (and tools bundling it): its ECDSA nonce generation for NIST P-521 keys was biased, so roughly 60 signatures — obtainable from a Git server or a rogue SSH host — could recover the private key. Mitigation: update to PuTTY 0.81+, revoke any P-521 key used with a vulnerable version, and prefer Ed25519 for new keys. It's a clean example of why key-type and library hygiene matter as much as key secrecy.",
          walkthroughUrl: "https://nvd.nist.gov/vuln/detail/CVE-2024-31497" },
      ],
    },
  ],
  certification: {
    code: "CCD", title: "CyberLab Certified Defender", passPercent: 80,
    exam: [
      { id: "ccd-1", prompt: "Stored XSS is the most dangerous kind because it:",
        options: [{ id: "a", text: "Only affects the attacker" }, { id: "b", text: "Is served to every user who views the page" }, { id: "c", text: "Requires physical access" }, { id: "d", text: "Cannot steal data" }], answer: "b" },
      { id: "ccd-2", prompt: "Which flag stops JavaScript reading a cookie?",
        options: [{ id: "a", text: "Secure" }, { id: "b", text: "SameSite" }, { id: "c", text: "HttpOnly" }, { id: "d", text: "Domain" }], answer: "c" },
      { id: "ccd-3", prompt: "The strongest single mitigation against inline-script XSS is:",
        options: [{ id: "a", text: "A faster server" }, { id: "b", text: "A Content-Security-Policy without unsafe-inline" }, { id: "c", text: "Hiding errors" }, { id: "d", text: "A longer password" }], answer: "b" },
      { id: "ccd-4", prompt: "An SSH private key should have permissions:",
        options: [{ id: "a", text: "777" }, { id: "b", text: "644" }, { id: "c", text: "600" }, { id: "d", text: "666" }], answer: "c" },
      { id: "ccd-5", prompt: "To avoid exposing your SSH agent on an intermediate host, prefer:",
        options: [{ id: "a", text: "ForwardAgent yes" }, { id: "b", text: "ProxyJump (ssh -J)" }, { id: "c", text: "Sharing your private key" }, { id: "d", text: "Disabling encryption" }], answer: "b" },
    ],
  },
});

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
      tool: r.tool, toolHref: r.toolHref, videoUrl: r.videoUrl, lab: Boolean(r.lab), resources: r.resources,
      tasks: r.tasks.map((task) => ({
        id: task.id, title: task.title, instructions: task.instructions,
        hint: task.hint, videoUrl: task.videoUrl, requiresAnswer: Boolean(task.answer),
        // writeup/walkthrough are spoilers — gated behind /api/academy/writeup.
        hasWriteup: Boolean(task.writeup || task.walkthroughUrl),
      })),
    })),
    certification: t.certification ? {
      code: t.certification.code, title: t.certification.title, passPercent: t.certification.passPercent,
      exam: t.certification.exam.map(({ id, prompt, options }) => ({ id, prompt, options })),
    } : null,
  }));
}
