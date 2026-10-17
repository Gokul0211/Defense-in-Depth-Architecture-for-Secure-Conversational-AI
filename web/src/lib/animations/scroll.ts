"use client";
import { motion, ScrollTrigger, prefersReducedMotion } from "./core";

/** Runs `build` once when `trigger` enters; reduced motion jumps to the end state. */
export function onEnter(trigger: Element, build: () => gsap.core.Timeline | gsap.core.Tween, start = "top 80%") {
  let played = false;
  const st = ScrollTrigger.create({
    trigger, start, once: true,
    onEnter: () => { if (played) return; played = true; const a = build(); if (prefersReducedMotion()) a.progress(1); },
  });
  return () => st.kill();
}

/** Progress (0..1) of `trigger` across the viewport, without a scroll listener. */
export function onProgress(trigger: Element, cb: (p: number) => void, opts: { start?: string; end?: string } = {}) {
  const st = ScrollTrigger.create({ trigger, start: opts.start ?? "top bottom", end: opts.end ?? "bottom top", onUpdate: (self) => cb(self.progress) });
  return () => st.kill();
}

export { motion, ScrollTrigger };
