"use client";
import { motion, prefersReducedMotion, isCoarsePointer } from "./core";

const disabled = () => prefersReducedMotion() || isCoarsePointer();

export function createMagneticInteraction(el: HTMLElement, { strength = 0.28, radius = 90 } = {}) {
  if (disabled()) return () => {};
  const xTo = motion.quickTo(el, "x", { duration: 0.5, ease: "elastic.out(1, 0.6)" });
  const yTo = motion.quickTo(el, "y", { duration: 0.5, ease: "elastic.out(1, 0.6)" });
  const move = (e: PointerEvent) => {
    const r = el.getBoundingClientRect();
    const dx = e.clientX - (r.left + r.width / 2), dy = e.clientY - (r.top + r.height / 2);
    if (Math.hypot(dx, dy) < radius + Math.max(r.width, r.height) / 2) { xTo(dx * strength); yTo(dy * strength); } else { xTo(0); yTo(0); }
  };
  const leave = () => { xTo(0); yTo(0); };
  window.addEventListener("pointermove", move, { passive: true });
  el.addEventListener("pointerleave", leave);
  return () => { window.removeEventListener("pointermove", move); el.removeEventListener("pointerleave", leave); xTo(0); yTo(0); };
}

export function createTiltInteraction(el: HTMLElement, { max = 4 } = {}) {
  if (disabled()) return () => {};
  motion.set(el, { transformPerspective: 900 });
  const rx = motion.quickTo(el, "rotationX", { duration: 0.6, ease: "power3.out" });
  const ry = motion.quickTo(el, "rotationY", { duration: 0.6, ease: "power3.out" });
  const move = (e: PointerEvent) => {
    const r = el.getBoundingClientRect();
    const px = (e.clientX - r.left) / r.width - 0.5, py = (e.clientY - r.top) / r.height - 0.5;
    ry(px * max * 2); rx(-py * max * 2);
  };
  const leave = () => { rx(0); ry(0); };
  el.addEventListener("pointermove", move); el.addEventListener("pointerleave", leave);
  return () => { el.removeEventListener("pointermove", move); el.removeEventListener("pointerleave", leave); motion.set(el, { rotationX: 0, rotationY: 0 }); };
}

/** Border light under the cursor: writes CSS variables only, no layout work. */
export function createSpotlightInteraction(el: HTMLElement) {
  const move = (e: PointerEvent) => {
    const r = el.getBoundingClientRect();
    el.style.setProperty("--mx", `${e.clientX - r.left}px`);
    el.style.setProperty("--my", `${e.clientY - r.top}px`);
  };
  el.addEventListener("pointermove", move);
  return () => el.removeEventListener("pointermove", move);
}

export function createParallaxInteraction(el: HTMLElement, { depth = 0.5 } = {}) {
  if (disabled()) return () => {};
  const xTo = motion.quickTo(el, "x", { duration: 0.8, ease: "power3.out" });
  const yTo = motion.quickTo(el, "y", { duration: 0.8, ease: "power3.out" });
  const move = (e: PointerEvent) => {
    xTo(((e.clientX / window.innerWidth) - 0.5) * 12 * depth);
    yTo(((e.clientY / window.innerHeight) - 0.5) * 12 * depth);
  };
  window.addEventListener("pointermove", move, { passive: true });
  return () => window.removeEventListener("pointermove", move);
}
