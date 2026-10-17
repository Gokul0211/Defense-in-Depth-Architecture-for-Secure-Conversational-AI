"use client";
import { useRef } from "react";
import { AnimatedCounter } from "@/components/animation/AnimatedCounter";
import { ScrollReveal } from "@/components/animation/ScrollReveal";
import { SourceNote } from "@/components/ui/SourceNote";
import { Stat } from "@/components/ui/Stat";
import { useGsap } from "@/hooks/useGsap";
import { motion, prefersReducedMotion } from "@/lib/animations/core";
import { onEnter } from "@/lib/animations/scroll";
import { dur, ease } from "@/lib/animations/tokens";
import { LIVE_ROWS, fact } from "@/lib/content/facts";

const TASKS = 34; // benign tasks in the live-agent run (README, Results, AgentDojo)
const done = (id: string) => Math.round(fact(LIVE_ROWS.find((r) => r.id === id)!.util).value * TASKS);
const BASE = done("none");

export function LiveMetrics() {
  const root = useRef<HTMLElement>(null);
  useGsap(root, () => {
    const el = root.current; if (!el || prefersReducedMotion()) return;
    const bars = el.querySelectorAll<HTMLElement>("[data-bar]");
    const cells = el.querySelectorAll<HTMLElement>("[data-cell]");
    const broken = el.querySelectorAll<HTMLElement>("[data-broken]");
    motion.set(bars, { scaleX: 0, transformOrigin: "0 50%" });
    motion.set(cells, { opacity: 0, scale: 0.4 });
    return onEnter(el.querySelector("[data-rows]")!, () => {
      const tl = motion.timeline();
      tl.to(bars, { scaleX: 1, duration: dur.long * 1.4, ease: ease.out, stagger: 0.14 }, 0);
      tl.to(cells, { opacity: 1, scale: 1, duration: 0.3, stagger: { each: 0.004, from: "start" }, ease: "back.out(2)" }, 0.3);
      // the built-in detector's cost: tasks that used to succeed flash orange, then go dark
      tl.to(broken, { backgroundColor: "var(--signal)", duration: 0.25, stagger: 0.07 }, 1.6);
      tl.to(broken, { backgroundColor: "var(--ink-3)", duration: 0.7, stagger: 0.07, ease: "power2.out" }, 2.0);
      return tl;
    }, "top 70%");
  }, []);

  return (
    <section ref={root} aria-labelledby="metrics-title" className="relative py-28 md:py-44">
      <div className="container-x">
        <ScrollReveal>
          <h2 id="metrics-title" className="display max-w-[18ch]">The cheap fix breaks the product</h2>
          <p className="mt-6 max-w-[46ch] text-xl text-bone-2">A live Gemini agent does email, banking, travel and Slack tasks while attackers plant instructions in its tool outputs. Lower attack success is better. Each square is a normal task the agent completed.</p>
        </ScrollReveal>

        <div data-rows className="mt-16 space-y-10">
          {LIVE_ROWS.map((r) => {
            const a = fact(r.asr), n = done(r.id);
            return (
              <div key={r.id} className="grid items-center gap-x-8 gap-y-4 lg:grid-cols-[14rem_1fr_21rem]">
                <p className="text-lg font-medium">{r.name}</p>
                <div className="flex items-center gap-4">
                  <div data-bar className="h-8" style={{ width: `${Math.max(1, a.value * 100)}%`, background: r.id === "none" ? "var(--bone-3)" : "var(--signal)" }} role="img" aria-label={`Attack success ${a.display}`} />
                  <AnimatedCounter value={a.value} display={a.display} className="num text-3xl font-medium" /><SourceNote source={a.source} />
                </div>
                <div>
                  <div className="grid grid-cols-[repeat(17,minmax(0,1fr))] gap-1" role="img" aria-label={`${n} of ${TASKS} normal tasks completed`}>
                    {Array.from({ length: TASKS }).map((_, i) => {
                      const ok = i < n;
                      const wasBroken = r.id === "detector" && i >= n && i < BASE;
                      return <span key={i} data-cell data-broken={wasBroken ? "" : undefined} className="aspect-square" style={{ background: ok ? "var(--bone)" : wasBroken ? "var(--bone)" : "var(--ink-3)" }} />;
                    })}
                  </div>
                  <p className="num mt-2 text-sm text-bone-2">{n} of {TASKS} normal tasks done</p>
                </div>
              </div>
            );
          })}
        </div>

        <p className="mt-12 max-w-[56ch] text-lg text-bone">
          The built-in detector reaches {fact("live.detector.asr").display} by breaking <span className="num text-signal">{fact("live.detector.broken").display}</span> normal tasks. DIDA's tool-call check keeps every one of them. The full defense stopped {fact("live.full.stopped").display} attacks.
          <SourceNote source="README, Results, AgentDojo" />
        </p>

        <div className="mt-24 grid gap-12 sm:grid-cols-2 lg:grid-cols-4">
          <Stat value={fact("l1h.wjb.auroc").display} label="WildJailbreak AUROC for the harm head" source={fact("l1h.wjb.auroc").source} />
          <Stat value={fact("l3.tomgibbs.auroc").display} label="Cipher jailbreak AUROC, tom-gibbs" source={fact("l3.tomgibbs.auroc").source} />
          <Stat value={fact("l4.injecagent.recall").display} label="InjecAgent recall, zero false positives" source={fact("l4.injecagent.recall").source} />
          <Stat value={fact("pipeline.blocked").display} label="DIDA-Bench attacks blocked, zero false positives" source={fact("pipeline.blocked").source} />
        </div>
      </div>
    </section>
  );
}
