"use client";
import { useEffect } from "react";
import { usePathname } from "next/navigation";
import Lenis from "lenis";
import "lenis/dist/lenis.css";
import { motion, ScrollTrigger, prefersReducedMotion, isCoarsePointer } from "@/lib/animations/core";

/**
 * Lenis smooth scroll, driven by GSAP's ticker so ScrollTrigger stays in step (the integration Lenis documents).
 * Off on the console (dense panes scroll natively), for reduced motion, and on touch devices.
 */
export function SmoothScroll() {
  const pathname = usePathname();
  useEffect(() => {
    if (pathname.startsWith("/console") || prefersReducedMotion() || isCoarsePointer()) return;
    const lenis = new Lenis({ lerp: 0.1, smoothWheel: true, anchors: true });
    lenis.on("scroll", ScrollTrigger.update);
    const tick = (t: number) => lenis.raf(t * 1000);
    motion.ticker.add(tick);
    motion.ticker.lagSmoothing(0);
    return () => { motion.ticker.remove(tick); lenis.destroy(); motion.ticker.lagSmoothing(500, 33); };
  }, [pathname]);
  return null;
}
