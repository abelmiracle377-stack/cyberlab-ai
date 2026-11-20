"use client";

import { useEffect, useRef } from "react";

// A subtle, balanced binary-field background: faint falling 0/1 glyphs on the
// obsidian canvas, with an occasional cyan highlight. Motion is purely
// decorative, sits behind all content, and pauses under prefers-reduced-motion.
export default function CyberBackground() {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const reduce = typeof window !== "undefined"
      && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

    const fontSize = 16;
    let width = 0, height = 0, drops: number[] = [], raf = 0;

    const resize = () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
      const columns = Math.max(1, Math.floor(width / fontSize));
      drops = new Array(columns).fill(0).map(() => Math.random() * -60);
    };
    resize();
    window.addEventListener("resize", resize);

    if (reduce) {
      // Static sparse field — no animation.
      ctx.fillStyle = "#0D1117";
      ctx.fillRect(0, 0, width, height);
      ctx.font = `${fontSize}px JetBrains Mono, monospace`;
      ctx.fillStyle = "rgba(46,160,67,0.14)";
      for (let i = 0; i < drops.length; i++) {
        ctx.fillText(Math.random() > 0.5 ? "0" : "1", i * fontSize, Math.random() * height);
      }
      return () => window.removeEventListener("resize", resize);
    }

    const draw = () => {
      ctx.fillStyle = "rgba(13,17,23,0.10)"; // obsidian fade -> gentle trails
      ctx.fillRect(0, 0, width, height);
      ctx.font = `${fontSize}px JetBrains Mono, monospace`;
      for (let i = 0; i < drops.length; i++) {
        const x = i * fontSize;
        const y = drops[i] * fontSize;
        ctx.fillStyle = Math.random() > 0.986
          ? "rgba(88,166,255,0.55)"   // rare electric-cyan highlight
          : "rgba(46,160,67,0.72)";   // phosphor mint
        ctx.fillText(Math.random() > 0.5 ? "0" : "1", x, y);
        if (y > height && Math.random() > 0.975) drops[i] = 0;
        drops[i] += 0.45;
      }
      raf = requestAnimationFrame(draw);
    };
    draw();

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
    };
  }, []);

  return <canvas ref={ref} className="cyber-bg" aria-hidden="true" />;
}
