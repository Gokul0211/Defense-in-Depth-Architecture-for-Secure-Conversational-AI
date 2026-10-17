"use client";
import { motion, prefersReducedMotion } from "./core";
import { dur, ease, stagger as stg } from "./tokens";

export interface RevealTextOpts { by?: "char" | "word"; blur?: number; stagger?: number; delay?: number; y?: number; paused?: boolean }

/**
 * Splits an element's text into spans and reveals them. The full string is kept in aria-label
 * and the split spans are aria-hidden. Returns the timeline and a revert function.
 */
export function revealText(el: HTMLElement, o: RevealTextOpts = {}) {
  const original = el.textContent ?? "";
  const by = o.by ?? "word";
  el.setAttribute("aria-label", original);
  el.textContent = "";
  const units = by === "word" ? original.split(/(\s+)/) : Array.from(original);
  const spans: HTMLElement[] = [];
  units.forEach((u) => {
    if (/^\s+$/.test(u)) { el.append(document.createTextNode(u)); return; }
    const s = document.createElement("span");
    s.textContent = u; s.setAttribute("aria-hidden", "true");
    s.style.display = "inline-block"; s.style.willChange = "transform, opacity, filter";
    el.append(s); spans.push(s);
  });
  const tl = motion.timeline({ paused: o.paused, delay: o.delay ?? 0 });
  if (prefersReducedMotion()) {
    tl.fromTo(spans, { opacity: 0 }, { opacity: 1, duration: 0.2 });
  } else {
    tl.fromTo(
      spans,
      { opacity: 0, y: o.y ?? 24, filter: `blur(${o.blur ?? 8}px)` },
      { opacity: 1, y: 0, filter: "blur(0px)", duration: dur.long, ease: ease.out, stagger: o.stagger ?? (by === "word" ? stg.word : stg.char), clearProps: "filter,transform,willChange" },
    );
  }
  return { timeline: tl, revert: () => { tl.kill(); el.textContent = original; el.removeAttribute("aria-label"); } };
}
