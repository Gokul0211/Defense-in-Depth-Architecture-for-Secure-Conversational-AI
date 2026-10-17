"use client";
import { useRef } from "react";
import { MagneticLink } from "@/components/animation/MagneticButton";
import { ButtonLink } from "@/components/ui/Button";
import { LabyrinthCanvasLazy } from "@/components/three/lazy";
import { useGsap } from "@/hooks/useGsap";
import { heroEntrance } from "@/lib/animations/hero";
import { prefersReducedMotion } from "@/lib/animations/core";
import type { CanvasReady } from "@/components/three/LabyrinthCanvas";
import { ROUTES } from "@/lib/constants/routes";

export function Hero() {
  const root = useRef<HTMLElement>(null);
  const attach = useRef<((r: CanvasReady) => void) | null>(null);
  const pending = useRef<CanvasReady | null>(null);

  useGsap(root, () => {
    const el = root.current; if (!el) return;
    const { attachScene, revert } = heroEntrance(el);
    attach.current = (r) => { if (!r.reduced) attachScene(r.handle); };
    if (pending.current) attach.current(pending.current);
    return () => { revert(); attach.current = null; };
  }, []);

  const onReady = (r: CanvasReady) => {
    if (prefersReducedMotion()) return;
    if (attach.current) attach.current(r); else pending.current = r;
  };

  return (
    <section ref={root} aria-labelledby="hero-title" className="relative flex min-h-[100dvh] items-center overflow-x-clip pt-24">
      <div className="container-x grid w-full items-center gap-10 lg:grid-cols-12 lg:gap-6">
        <div className="lg:col-span-6">
          <h1 id="hero-title" data-hero-title data-reveal className="display" style={{ whiteSpace: "pre-line" }}>{"Five layers.\nNo straight path in."}</h1>
          <p data-hero-sub data-reveal className="measure mt-6 max-w-[34ch] text-lg text-bone-2">
            DIDA screens every prompt, document, tool call and reply for LLM apps, and measures what layered defenses actually catch.
          </p>
          <div className="mt-9 flex flex-wrap items-center gap-x-7 gap-y-4">
            <span data-hero-cta data-reveal><MagneticLink href={ROUTES.console}>Open console</MagneticLink></span>
            <span data-hero-cta data-reveal><ButtonLink href={ROUTES.research} variant="link" arrow>Read the research</ButtonLink></span>
          </div>
        </div>
        <div className="relative lg:col-span-6" style={{ marginRight: "calc(-1 * max(2rem, (100vw - 1360px) / 2 + 2rem))" }}>
          <div data-accent-anchor className="relative aspect-square w-full md:aspect-[5/4]">
            <LabyrinthCanvasLazy onReady={onReady} label="Abstract 3D illustration of the DIDA architecture: five nested walls, each with one opening, around a protected core. It is an illustration, not a data display." />
          </div>
          <p className="mt-2 text-xs text-bone-3">Illustration of the architecture, not live data.</p>
        </div>
      </div>
    </section>
  );
}
