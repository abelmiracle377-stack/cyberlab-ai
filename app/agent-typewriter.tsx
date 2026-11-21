"use client";

import { Fragment, type ReactNode } from "react";

// Terminal-style token coloring for the agent's plain-text output.
const TOKEN = new RegExp([
  "(CYBERLAB\\{[^}]{1,80}\\})",                               // flags
  "(CVE-\\d{4}-\\d{3,7})",                                    // CVEs
  "(\\bT\\d{4}(?:\\.\\d{3})?\\b)",                            // ATT&CK techniques
  "(https?://[^\\s)]+)",                                      // URLs
  "(\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b)",                       // IPv4
  "(\\b[0-9a-fA-F]{32,64}\\b)",                               // hashes
  "(\\b(?:OK|PASS|PASSED|SUCCESS|VERIFIED|ACTIVE|OPEN)\\b)",  // positive
  "(\\b(?:WARN|WARNING|PENDING|MEDIUM)\\b)",                  // caution
  "(\\b(?:ERROR|ERR|FAIL|FAILED|CRITICAL|DENIED|SEVERED|HIGH)\\b)", // negative
].join("|"), "g");

const CLASS: Record<number, string> = { 1: "tw-flag", 2: "tw-amber", 3: "tw-cyan", 4: "tw-cyan", 5: "tw-cyan", 6: "tw-dim", 7: "tw-mint", 8: "tw-amber", 9: "tw-crimson" };

function colorize(text: string): ReactNode[] {
  const out: ReactNode[] = [];
  let last = 0, key = 0, m: RegExpExecArray | null;
  TOKEN.lastIndex = 0;
  while ((m = TOKEN.exec(text)) !== null) {
    if (m.index > last) out.push(<Fragment key={key++}>{text.slice(last, m.index)}</Fragment>);
    let cls = "tw-cyan";
    for (let g = 1; g <= 9; g++) if (m[g] !== undefined) { cls = CLASS[g]; break; }
    out.push(<span key={key++} className={cls}>{m[0]}</span>);
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(<Fragment key={key++}>{text.slice(last)}</Fragment>);
  return out;
}

// Renders the agent's real reply text immediately. No typing animation or sound.
export default function AgentTypewriter({ text }: { text: string }) {
  return <span className="agent-tw">{colorize(text)}</span>;
}
