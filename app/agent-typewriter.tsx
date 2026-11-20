"use client";

import { Fragment, useEffect, useRef, useState, type ReactNode } from "react";

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

export default function AgentTypewriter({ text, animate, generating, sound }: { text: string; animate: boolean; generating: boolean; sound: boolean }) {
  const [n, setN] = useState(animate ? 0 : text.length);
  const ctxRef = useRef<AudioContext | null>(null);
  const lastClick = useRef(0);

  function click() {
    if (!sound) return;
    const now = performance.now();
    if (now - lastClick.current < 42) return; // throttle keystrokes
    lastClick.current = now;
    try {
      type WA = typeof AudioContext;
      const Ctor = (window.AudioContext || (window as unknown as { webkitAudioContext?: WA }).webkitAudioContext);
      if (!Ctor) return;
      const ctx = ctxRef.current ?? (ctxRef.current = new Ctor());
      if (ctx.state === "suspended") void ctx.resume();
      const o = ctx.createOscillator(), g = ctx.createGain();
      o.type = "square";
      o.frequency.value = 1300 + Math.random() * 700;
      g.gain.setValueAtTime(0.0001, ctx.currentTime);
      g.gain.exponentialRampToValueAtTime(0.03, ctx.currentTime + 0.002);
      g.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.03);
      o.connect(g).connect(ctx.destination);
      o.start();
      o.stop(ctx.currentTime + 0.035);
    } catch { /* audio unavailable */ }
  }

  useEffect(() => {
    if (!animate) { setN(text.length); return; }
    const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    if (reduce) { setN(text.length); return; }
    let raf = 0, last = performance.now(), acc = 0;
    const loop = (t: number) => {
      acc += t - last; last = t;
      let typed = 0;
      setN((prev) => {
        let cur = prev;
        while (acc >= 16 && cur < text.length) {
          const behind = text.length - cur;
          const step = behind > 240 ? 7 : behind > 60 ? 2 : 1; // catch up to streamed text
          cur = Math.min(text.length, cur + step);
          acc -= 16; typed += step;
        }
        return cur;
      });
      if (typed > 0) click();
      raf = requestAnimationFrame(loop);
    };
    raf = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(raf);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [animate, text]);

  const shown = n >= text.length ? text : text.slice(0, n);
  const caret = animate && (n < text.length || generating);
  return <span className="agent-tw">{colorize(shown)}{caret && <span className="agent-tw-caret">▋</span>}</span>;
}
