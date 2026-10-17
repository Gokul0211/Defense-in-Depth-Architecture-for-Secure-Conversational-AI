"use client";
import { useEffect, useRef, useState } from "react";
import { SourceNote } from "@/components/ui/SourceNote";
import { ScrollReveal } from "@/components/animation/ScrollReveal";
import { FINDINGS } from "@/lib/content/contributions";
import { BlindFig, OverlapFig, BudgetFig, BitFig, StackFig, HeadroomFig } from "./Figures";
import clsx from "clsx";

const FIGS = [<BlindFig key="1" />, <OverlapFig key="2" />, <BudgetFig key="3" />, <BitFig key="4" />, <StackFig key="5" />, <HeadroomFig key="6" />];

/** Six findings as six chapters, each with an interactive figure. A rail tracks the active chapter. */
export function Chapters() {
  const [active, setActive] = useState(0);
  const refs = useRef<(HTMLElement | null)[]>([]);
  useEffect(() => {
    const io = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) setActive(Number((e.target as HTMLElement).dataset.i)); }), { rootMargin: "-45% 0px -45% 0px" });
    refs.current.forEach((r) => r && io.observe(r));
    return () => io.disconnect();
  }, []);
  return (
    <section aria-labelledby="findings" className="relative mt-24">
      <h2 id="findings" className="sr-only-text">Six findings</h2>
      <nav aria-label="Findings" className="fixed left-5 top-1/2 z-20 hidden -translate-y-1/2 xl:block">
        <ol className="space-y-3">{FINDINGS.map((f, i) => (
          <li key={f.n}><a href={`#finding-${f.n}`} aria-label={`Finding ${f.n}: ${f.title}`} aria-current={active === i ? "true" : undefined} className="flex items-center gap-3 text-xs">
            <span className={clsx("block h-0.5 transition-all duration-300", active === i ? "w-8 bg-signal" : "w-4 bg-line-strong")} /><span className={clsx("num transition-colors", active === i ? "text-bone" : "text-bone-3")}>{f.n}</span>
          </a></li>
        ))}</ol>
      </nav>
      {FINDINGS.map((f, i) => (
        <article key={f.n} id={`finding-${f.n}`} data-i={i} ref={(el) => { refs.current[i] = el; }} className="grid min-h-[88vh] items-center gap-10 border-t border-line py-16 lg:grid-cols-2 lg:gap-16">
          <ScrollReveal>
            <p className="num text-sm text-signal">Finding {f.n} of 6</p>
            <h3 className="mt-3 max-w-[22ch] text-3xl font-semibold tracking-tight md:text-5xl">{f.title}</h3>
            <p className="mt-6 max-w-[48ch] text-lg leading-relaxed text-bone-2">{f.evidence}<SourceNote source={`README, Research finding ${f.n}`} /></p>
          </ScrollReveal>
          <div>{FIGS[i]}</div>
        </article>
      ))}
    </section>
  );
}
