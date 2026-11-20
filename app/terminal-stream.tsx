"use client";

import { useEffect, useState } from "react";

// Streams log lines in one at a time at slightly varied speed, with a blinking
// block cursor on the active line — the "live terminal" feel real tools have,
// instead of dumping a wall of text. Honors prefers-reduced-motion.
export default function TerminalStream({ lines, className = "" }: { lines: string[]; className?: string }) {
  const [shown, setShown] = useState(0);

  useEffect(() => {
    if (lines.length === 0) { setShown(0); return; }
    const reduce = typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    if (reduce) { setShown(lines.length); return; }
    setShown(0);
    let i = 0;
    let timer: ReturnType<typeof setTimeout>;
    const tick = () => {
      i += 1;
      setShown(i);
      if (i < lines.length) timer = setTimeout(tick, 55 + Math.random() * 120); // 55–175ms per line
    };
    timer = setTimeout(tick, 70);
    return () => clearTimeout(timer);
  }, [lines]);

  return (
    <div className={className} style={{ fontFamily: "var(--mono)" }}>
      {lines.slice(0, shown).map((line, i) => (
        <div key={i} className={"whitespace-pre-wrap break-all text-[11px] leading-5" + (i === shown - 1 ? " anim-caret" : "")}>
          <span style={{ color: "var(--green)" }}>&gt;</span> {line}
        </div>
      ))}
    </div>
  );
}
