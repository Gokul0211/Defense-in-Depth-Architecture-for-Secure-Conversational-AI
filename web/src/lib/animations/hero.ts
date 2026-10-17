"use client";
import { motion, prefersReducedMotion } from "./core";
import { revealText } from "./text";
import { dur, ease } from "./tokens";
import type { LabyrinthHandle } from "@/lib/three/labyrinth-scene";

/** Scene beat of the hero entrance: walls rise outer to inner, camera dollies ~8% closer, core ignites last. */
export function sceneIntro(h: LabyrinthHandle) {
  const s = h.state;
  const tl = motion.timeline();
  // tween each wall explicitly: outer to inner, 120 ms apart
  s.rise.forEach((_, i) => tl.to(s.rise, { [i]: 1, duration: dur.long, ease: ease.out }, i * 0.12));
  tl.fromTo(s.cam, { distance: 18.4 }, { distance: 17, duration: 1.5, ease: ease.inOut }, 0);
  tl.to(s, { core: 1, duration: 0.8, ease: "power2.out" }, 0.9);
  tl.fromTo(s, { pulse: 0 }, { pulse: 1, duration: 0.4, yoyo: true, repeat: 1, ease: "power2.inOut" }, 0.9);
  return tl;
}

/** One timeline, about 2.2 s. Scene beat is attached when the canvas is ready. */
export function heroEntrance(root: HTMLElement) {
  const q = (s: string) => root.querySelector<HTMLElement>(s);
  const h1 = q("[data-hero-title]"), sub = q("[data-hero-sub]"), ctas = root.querySelectorAll("[data-hero-cta]");
  const tl = motion.timeline();
  let revert = () => {};
  if (h1) {
    motion.set(h1, { opacity: 1 });
    const r = revealText(h1, { by: "word", paused: true });
    revert = r.revert;
    tl.add(r.timeline.paused(false), 0.26);
  }
  if (prefersReducedMotion()) {
    tl.to([sub, ...ctas], { opacity: 1, duration: 0.2 }, 0);
  } else {
    if (sub) tl.fromTo(sub, { opacity: 0, y: 14 }, { opacity: 1, y: 0, duration: dur.base, ease: ease.out }, 0.7);
    tl.fromTo(ctas, { opacity: 0, scale: 0.96 }, { opacity: 1, scale: 1, duration: dur.base, ease: ease.out, stagger: 0.08, clearProps: "transform" }, 1.05);
  }
  const attachScene = (h: LabyrinthHandle) => {
    const scene = sceneIntro(h);
    if (tl.progress() < 1 && tl.time() < 0.9) tl.add(scene, 0.9); else scene.play(0);
  };
  return { timeline: tl, attachScene, revert };
}
