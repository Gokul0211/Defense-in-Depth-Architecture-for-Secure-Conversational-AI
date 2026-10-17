"use client";
import { useEffect, useRef } from "react";
import { motion, prefersReducedMotion } from "@/lib/animations/core";
import { LAYER_NAMES } from "@/lib/console-utils";

const NODES = ["L1", "L2", "L3", "L4", "L5"];
export type PipeState = "idle" | "running" | "done";

/** Request travels the layers this tool uses and stops where the decision lands. */
export function Pipeline({ used, stopLayer, state }: { used: string[]; stopLayer: string | null; state: PipeState }) {
  const root = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = root.current; if (!el) return;
    const dots = Array.from(el.querySelectorAll<HTMLElement>("[data-node]"));
    const bar = el.querySelector<HTMLElement>("[data-bar]");
    if (state === "idle") { motion.set(dots, { backgroundColor: "rgba(0,0,0,0)" }); if (bar) motion.set(bar, { scaleX: 0 }); return; }
    if (prefersReducedMotion()) {
      dots.forEach((d) => { const l = d.dataset.node!; d.style.backgroundColor = state === "done" && l === stopLayer ? "var(--signal)" : used.includes(l) ? "var(--bone)" : "transparent"; });
      if (bar) bar.style.transform = "scaleX(1)";
      return;
    }
    const tl = motion.timeline();
    const usedDots = dots.filter((d) => used.includes(d.dataset.node!));
    if (bar) tl.fromTo(bar, { scaleX: 0 }, { scaleX: state === "done" && stopLayer ? (NODES.indexOf(stopLayer) + 0.5) / NODES.length : 1, duration: state === "running" ? 2.4 : 0.8, ease: "power2.inOut" }, 0);
    usedDots.forEach((d, i) => tl.to(d, { backgroundColor: state === "done" && d.dataset.node === stopLayer ? "#ff4f1f" : "#efebe3", duration: 0.2 }, 0.15 + i * 0.18));
    return () => { tl.kill(); };
  }, [used, stopLayer, state]);

  return (
    <div ref={root} className="surface-1 p-5" aria-label="Pipeline" role="group">
      <div className="relative grid grid-cols-5">
        <div aria-hidden className="absolute left-[10%] right-[10%] top-[11px] h-px bg-line-strong" />
        <div aria-hidden data-bar className="absolute left-[10%] right-[10%] top-[10px] h-0.5 origin-left bg-signal" style={{ transform: "scaleX(0)" }} />
        {NODES.map((n) => (
          <div key={n} className="relative flex flex-col items-center gap-2 text-center" style={{ opacity: used.includes(n) ? 1 : 0.35 }}>
            <span data-node={n} className="grid size-6 place-items-center border-2 border-bone-2 bg-ink-1" style={{ backgroundColor: "rgba(0,0,0,0)" }} />
            <span className="num text-xs text-bone">{n}</span>
            <span className="hidden text-xs text-bone-3 sm:block">{LAYER_NAMES[n]}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
