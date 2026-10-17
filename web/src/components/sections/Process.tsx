"use client";
import { useEffect, useRef, useState } from "react";
import { CodeBlock } from "@/components/ui/CodeBlock";
import { ScrollReveal } from "@/components/animation/ScrollReveal";
import { motion, prefersReducedMotion } from "@/lib/animations/core";
import clsx from "clsx";

const STEPS = [
  { title: "Install", body: "Install the proxy's requirements.", code: "pip install -r requirements.txt" },
  { title: "Run", body: "Start the proxy and the API on port 8080.", code: "python main.py" },
  { title: "Point your app at the proxy", body: "It speaks the OpenAI chat completions format.", code: 'curl http://localhost:8080/v1/chat/completions \\\n  -H "Content-Type: application/json" \\\n  -d \'{"model": "your-model", "messages": [{"role": "user", "content": "Hello"}]}\'' },
  { title: "Wire agent tools", body: "Authorize a call before it runs, and scan the output after.", code: "POST /sentinel/agent/tool_call       # before execution\nPOST /sentinel/agent/tool_response   # after, on the tool output" },
];

export function Process() {
  const [i, setI] = useState(0);
  const codeRef = useRef<HTMLDivElement>(null);
  const first = useRef(true);
  const rail = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (first.current) { first.current = false; return; }
    if (prefersReducedMotion() || !codeRef.current) return;
    motion.fromTo(codeRef.current, { opacity: 0, x: 8 }, { opacity: 1, x: 0, duration: 0.14 });
  }, [i]);
  useEffect(() => { if (rail.current) motion.to(rail.current, { scaleY: (i + 1) / STEPS.length, duration: 0.26, ease: "power3.out" }); }, [i]);
  return (
    <section aria-labelledby="process-title" className="relative py-28 md:py-36">
      <div className="container-x">
        <ScrollReveal><h2 id="process-title" className="h2 max-w-[20ch]">Put it in front of your app</h2></ScrollReveal>
        <div className="mt-14 grid gap-10 lg:grid-cols-[22rem_1fr]">
          <ol className="relative pl-6">
            <span aria-hidden className="absolute bottom-0 left-0 top-0 w-px bg-line-strong" />
            <div ref={rail} aria-hidden className="absolute bottom-0 left-0 top-0 w-px origin-top bg-signal" style={{ transform: "scaleY(0.25)" }} />
            {STEPS.map((s, k) => (
              <li key={s.title}>
                <button onClick={() => setI(k)} onFocus={() => setI(k)} aria-current={i === k ? "step" : undefined} className={clsx("block w-full py-4 text-left transition-colors", i === k ? "text-bone" : "text-bone-3 hover:text-bone-2")}>
                  <span className="block font-medium">{s.title}</span>
                  <span className="mt-1 block text-sm text-bone-2">{s.body}</span>
                </button>
              </li>
            ))}
          </ol>
          <div ref={codeRef} aria-live="polite"><CodeBlock code={STEPS[i].code} label={STEPS[i].title} /></div>
        </div>
      </div>
    </section>
  );
}
