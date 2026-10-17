"use client";
import { gsap } from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { ScrambleTextPlugin } from "gsap/ScrambleTextPlugin";
import { dur, ease } from "./tokens";

let registered = false;
export function registerMotion() {
  if (registered || typeof window === "undefined") return;
  gsap.registerPlugin(ScrollTrigger, ScrambleTextPlugin);
  registered = true;
}
registerMotion();

/** The one place animation libraries are imported. Call sites use the helpers below. */
export const motion = gsap;
export { ScrollTrigger };

export const prefersReducedMotion = () =>
  typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
export const isCoarsePointer = () =>
  typeof window !== "undefined" && window.matchMedia("(pointer: coarse)").matches;

type Target = gsap.TweenTarget;
export interface InOpts { y?: number; blur?: number; delay?: number; duration?: number; stagger?: number }

export function animateIn(targets: Target, o: InOpts = {}) {
  if (prefersReducedMotion()) return gsap.to(targets, { opacity: 1, duration: 0.2, clearProps: "filter,transform" });
  return gsap.fromTo(
    targets,
    { opacity: 0, y: o.y ?? 16, filter: o.blur ? `blur(${o.blur}px)` : "none" },
    { opacity: 1, y: 0, filter: "blur(0px)", duration: o.duration ?? dur.base, delay: o.delay ?? 0, stagger: o.stagger ?? 0, ease: ease.out, clearProps: "filter,transform" },
  );
}

export function animateOut(targets: Target, o: InOpts = {}) {
  return gsap.to(targets, { opacity: 0, y: o.y ?? -8, duration: o.duration ?? dur.short, ease: "power2.in" });
}

export function staggerReveal(targets: Target, o: InOpts = {}) {
  return animateIn(targets, { stagger: 0.07, ...o });
}

/** Stroke draw for SVG paths. */
export function drawPath(path: SVGGeometryElement, o: { duration?: number; delay?: number; from?: "start" | "end" } = {}) {
  const len = path.getTotalLength();
  if (prefersReducedMotion()) { path.style.strokeDasharray = "none"; path.style.strokeDashoffset = "0"; return gsap.to(path, { opacity: 1, duration: 0.2 }); }
  gsap.set(path, { strokeDasharray: len, strokeDashoffset: len });
  return gsap.to(path, { strokeDashoffset: 0, duration: o.duration ?? dur.long, delay: o.delay ?? 0, ease: ease.inOut, onComplete: () => { path.style.strokeDasharray = "none"; } });
}

/** Animate any plain object property, such as a Three.js uniform's `value` holder or camera rig. */
export function animateUniform<T extends object>(target: T, to: Partial<Record<keyof T, number>>, o: { duration?: number; delay?: number; ease?: string } = {}) {
  return gsap.to(target, { ...(to as gsap.TweenVars), duration: o.duration ?? dur.scene, delay: o.delay ?? 0, ease: o.ease ?? ease.inOut, overwrite: "auto" });
}
