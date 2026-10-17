"use client";
import { useRef, useState, useEffect, type ReactNode, type KeyboardEvent } from "react";
import { motion } from "@/lib/animations/core";
import { dur, ease } from "@/lib/animations/tokens";
import { prefersReducedMotion } from "@/lib/animations/core";
import clsx from "clsx";

export interface TabDef { id: string; label: string; icon?: ReactNode }

/** Accessible tabs with arrow-key roving focus and a sliding indicator. */
export function Tabs({ tabs, active, onChange, label, className, children }: {
  tabs: TabDef[]; active: string; onChange: (id: string) => void; label: string; className?: string; children?: ReactNode;
}) {
  const listRef = useRef<HTMLDivElement>(null);
  const indRef = useRef<HTMLSpanElement>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const list = listRef.current, ind = indRef.current;
    if (!list || !ind) return;
    const el = list.querySelector<HTMLElement>(`[data-tab="${active}"]`);
    if (!el) return;
    const to = { x: el.offsetLeft, width: el.offsetWidth };
    if (!ready || prefersReducedMotion()) { motion.set(ind, to); setReady(true); } else motion.to(ind, { ...to, duration: dur.short, ease: ease.out });
  }, [active, ready, tabs.length]);

  const onKey = (e: KeyboardEvent) => {
    const i = tabs.findIndex((t) => t.id === active);
    let n = i;
    if (e.key === "ArrowRight") n = (i + 1) % tabs.length;
    else if (e.key === "ArrowLeft") n = (i - 1 + tabs.length) % tabs.length;
    else if (e.key === "Home") n = 0; else if (e.key === "End") n = tabs.length - 1; else return;
    e.preventDefault(); onChange(tabs[n].id);
    listRef.current?.querySelector<HTMLElement>(`[data-tab="${tabs[n].id}"]`)?.focus();
  };

  return (
    <div className={className}>
      <div ref={listRef} role="tablist" aria-label={label} onKeyDown={onKey} className="relative flex w-full gap-1 overflow-x-auto border-b border-line pb-px">
        {tabs.map((t) => (
          <button key={t.id} role="tab" data-tab={t.id} id={`tab-${t.id}`} aria-selected={active === t.id} aria-controls={`panel-${t.id}`} tabIndex={active === t.id ? 0 : -1}
            onClick={() => onChange(t.id)}
            className={clsx("relative flex h-11 shrink-0 items-center gap-2 px-4 text-sm font-medium transition-colors", active === t.id ? "text-bone" : "text-bone-3 hover:text-bone-2")}>
            {t.icon}{t.label}
          </button>
        ))}
        <span ref={indRef} aria-hidden className="absolute bottom-0 left-0 h-0.5 bg-signal" style={{ width: 0 }} />
      </div>
      {children}
    </div>
  );
}

export function TabPanel({ id, active, children, className }: { id: string; active: string; children: ReactNode; className?: string }) {
  return <div role="tabpanel" id={`panel-${id}`} aria-labelledby={`tab-${id}`} hidden={active !== id} className={className}>{active === id && children}</div>;
}
