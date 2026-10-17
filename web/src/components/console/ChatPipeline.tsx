"use client";
import { useEffect, useRef, useState } from "react";
import clsx from "clsx";
import { motion, prefersReducedMotion } from "@/lib/animations/core";
import type { ChatResult, ChatStage } from "@/lib/api/types";
import type { ChatPhase } from "@/lib/state/chat-store";

const NODES = [
  { id: "L1", label: "Input" }, { id: "L2", label: "Docs" }, { id: "L3", label: "Convo" }, { id: "LLM", label: "Model" }, { id: "L5", label: "Output" },
] as const;
const STEP_MS = 170;

/**
 * The path one message takes through DIDA. While the request is in flight a pulse travels the nodes;
 * when the verdicts arrive each stage settles in order: passed, warned, or blocked (with a shockwave),
 * and stages the message never reached stay dark.
 */
export function ChatPipeline({ phase, stages, last }: { phase: ChatPhase; stages: ChatStage[] | null; last: ChatResult | null }) {
  const [cursor, setCursor] = useState(-1);
  const [revealed, setRevealed] = useState(-1);
  const ring = useRef<HTMLSpanElement>(null);

  // A message that is stopped never travels further, even though the backend scored every input layer for the record.
  const raw = (id: string) => stages?.find((s) => s.layer === id);
  // A cross-layer rule that fires after the model replied has no single failing score; show it on the last stage reached.
  const blockedId = stages?.find((s) => s.status === "BLOCKED")?.layer ?? (last?.stopped_at === "TIB" && stages?.length ? "L5" : null);
  const blockedIdx = NODES.findIndex((n) => n.id === blockedId);
  const by = (id: string): ChatStage | undefined => {
    const st = raw(id);
    return st && blockedIdx >= 0 && NODES.findIndex((n) => n.id === id) > blockedIdx ? { ...st, status: "SKIPPED", score: null } : st;
  };

  useEffect(() => {
    if (phase === "running") {
      setRevealed(-1); setCursor(0);
      if (prefersReducedMotion()) return;
      const id = setInterval(() => setCursor((c) => (c + 1) % NODES.length), 360);
      return () => clearInterval(id);
    }
    setCursor(-1);
    if (phase === "idle") { setRevealed(-1); return; }
    if (prefersReducedMotion()) { setRevealed(NODES.length - 1); return; }
    const timers = NODES.map((_, i) => setTimeout(() => setRevealed(i), i * STEP_MS));
    return () => timers.forEach(clearTimeout);
  }, [phase, stages]);

  // shockwave on the node that stopped the message, the moment it is revealed
  useEffect(() => {
    if (phase !== "done" || blockedIdx < 0 || revealed !== blockedIdx || !ring.current || prefersReducedMotion()) return;
    const t = motion.fromTo(ring.current, { scale: 1, opacity: 0.8 }, { scale: 3.2, opacity: 0, duration: 0.8, ease: "expo.out" });
    return () => { t.kill(); };
  }, [phase, revealed, blockedIdx]);

  const reachedIdx = phase === "done" && stages
    ? Math.max(-1, ...NODES.map((n, i) => (by(n.id) && by(n.id)!.status !== "SKIPPED" && i <= revealed ? i : -1)))
    : -1;
  const fillIdx = phase === "running" ? cursor : reachedIdx;
  const pct = fillIdx < 0 ? 0 : (fillIdx / (NODES.length - 1)) * 100;
  const stoppedStage = blockedId ? by(blockedId) : undefined;
  const stoppedName = blockedId ? NODES.find((n) => n.id === blockedId)?.label : null;
  const hot = Boolean(blockedId) && phase === "done";

  return (
    <div className="border-b border-line px-4 pb-3 pt-4" role="group" aria-label="Message path through the layers">
      <div className="relative grid grid-cols-5">
        <div aria-hidden className="absolute left-[10%] right-[10%] top-[13px] h-px bg-line-strong" />
        <div aria-hidden className={clsx("absolute left-[10%] top-[12px] h-0.5", hot ? "bg-signal" : "bg-bone-2")}
          style={{ width: `${pct * 0.8}%`, transition: `width ${phase === "running" ? 360 : STEP_MS}ms var(--ease-out)` }} />
        {NODES.map((n, i) => {
          const st = phase === "done" && i <= revealed ? by(n.id) : undefined;
          const status = st?.status;
          const active = phase === "running" && i === cursor;
          const passedByPulse = phase === "running" && i < cursor;
          return (
            <div key={n.id} className="relative flex flex-col items-center gap-1.5 text-center">
              <span className="relative grid size-[26px] place-items-center">
                {n.id === blockedId && <span ref={ring} aria-hidden className="absolute inset-0 border-2 border-signal opacity-0" />}
                <span aria-hidden className={clsx(
                  "size-[18px] border-2 transition-[background-color,border-color,transform,opacity] duration-200",
                  !status && !active && !passedByPulse && "border-bone-3 bg-transparent",
                  active && "scale-125 border-bone bg-bone",
                  passedByPulse && "border-bone-2 bg-bone-2/40",
                  status === "PASSED" && "border-bone bg-bone",
                  status === "WARNED" && "border-signal bg-signal-dim",
                  status === "BLOCKED" && "scale-125 border-signal bg-signal",
                  status === "SKIPPED" && "border-line-strong bg-transparent opacity-50",
                )} />
              </span>
              <span className={clsx("num text-[0.7rem]", status === "BLOCKED" ? "text-signal" : status === "SKIPPED" ? "text-bone-3" : "text-bone")}>{n.id}</span>
              <span className="num text-[0.65rem] leading-none text-bone-3">{status && st?.score != null ? st.score.toFixed(2) : n.label}</span>
            </div>
          );
        })}
      </div>
      <p className={clsx("num mt-3 min-h-4 text-[0.7rem]", hot ? "text-signal" : "text-bone-3")} aria-live="polite">
        {phase === "idle" && "Every message passes input, document, conversation, model and output checks."}
        {phase === "running" && "Checking..."}
        {phase === "done" && (blockedId
          ? last?.stopped_at === "TIB"
            ? `Stopped by cross-layer rule ${(last.rule ?? []).join(", ") || "on the evidence bus"}`
            : `Blocked at ${stoppedName} (${blockedId})${stoppedStage?.score != null ? `, score ${stoppedStage.score.toFixed(2)}` : ""}`
          : last?.stopped_at === "TIB" ? "Session terminated by an earlier rule."
            : stages?.some((s) => s.status === "WARNED") ? "Passed with a warning." : "Passed every layer.")}
      </p>
    </div>
  );
}
