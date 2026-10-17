"use client";
import { useMemo, useRef } from "react";
import { LabyrinthMark } from "@/components/brand/LabyrinthMark";
import { MagneticLink } from "@/components/animation/MagneticButton";
import { useGsap } from "@/hooks/useGsap";
import { drawPath, motion, prefersReducedMotion } from "@/lib/animations/core";
import { onEnter } from "@/lib/animations/scroll";
import { buildTracePath } from "@/lib/three/labyrinth-geometry";
import { ROUTES } from "@/lib/constants/routes";

/** The mark demonstrates its own meaning: hover the button and a path threads the five openings to the core. */
export function CtaBand() {
  const root = useRef<HTMLElement>(null);
  const trace = useMemo(() => buildTracePath(), []);
  useGsap(root, () => {
    const el = root.current; if (!el) return;
    const path = el.querySelector<SVGPathElement>(".trace"), core = el.querySelector<SVGRectElement>(".core");
    if (!path) return;
    let tl: gsap.core.Timeline | null = null;
    const play = () => {
      if (prefersReducedMotion()) { path.style.opacity = "1"; path.style.strokeDasharray = "none"; return; }
      tl?.kill(); path.style.opacity = "1";
      tl = motion.timeline().add(drawPath(path, { duration: 1.6 }));
      if (core) tl.fromTo(core, { scale: 1 }, { scale: 1.8, svgOrigin: "100 100", duration: 0.25, yoyo: true, repeat: 1 }, ">-0.1");
    };
    const stop = () => { tl?.kill(); motion.to(path, { opacity: 0, duration: 0.3 }); };
    const btn = el.querySelector("[data-cta-wrap]");
    if (!btn) return;
    const offEnter = onEnter(el, () => { play(); return motion.timeline(); }, "top 70%");
    btn.addEventListener("pointerenter", play); btn.addEventListener("focusin", play);
    btn.addEventListener("pointerleave", stop); btn.addEventListener("focusout", stop);
    return () => { offEnter(); btn.removeEventListener("pointerenter", play); btn.removeEventListener("focusin", play); btn.removeEventListener("pointerleave", stop); btn.removeEventListener("focusout", stop); tl?.kill(); };
  }, []);
  return (
    <section ref={root} aria-labelledby="cta-title" className="relative py-28 md:py-36">
      <div className="container-x grid items-center gap-10 border-y border-line py-16 md:grid-cols-[1fr_auto]">
        <div>
          <h2 id="cta-title" className="display max-w-[14ch]">Watch the layers work.</h2>
          <div data-cta-wrap className="mt-8 inline-block"><MagneticLink href={ROUTES.console}>Open console</MagneticLink></div>
        </div>
        <LabyrinthMark trace={trace} decorative className="size-64 md:size-96" />
      </div>
    </section>
  );
}
