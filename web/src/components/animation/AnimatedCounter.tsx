"use client";
import { useRef } from "react";
import { useGsap } from "@/hooks/useGsap";
import { motion, prefersReducedMotion } from "@/lib/animations/core";
import { onEnter } from "@/lib/animations/scroll";
import { dur, ease } from "@/lib/animations/tokens";

/** Counts from 0 to `value` once when it enters. `display` is the exact final string, shown to assistive tech and when motion is reduced. */
export function AnimatedCounter({ value, decimals = 3, suffix = "", display, className }: {
  value: number; decimals?: number; suffix?: string; display: string; className?: string;
}) {
  const ref = useRef<HTMLSpanElement>(null);
  useGsap(ref, () => {
    const el = ref.current; if (!el) return;
    if (prefersReducedMotion()) { el.textContent = display; return; }
    el.textContent = (0).toFixed(decimals) + suffix;
    return onEnter(el, () => {
      const o = { v: 0 };
      return motion.to(o, { v: value, duration: dur.long * 1.4, ease: ease.out, onUpdate: () => { el.textContent = o.v.toFixed(decimals) + suffix; }, onComplete: () => { el.textContent = display; } });
    }, "top 88%");
  }, [value, display]);
  return <span ref={ref} className={className} aria-label={display}>{display}</span>;
}
