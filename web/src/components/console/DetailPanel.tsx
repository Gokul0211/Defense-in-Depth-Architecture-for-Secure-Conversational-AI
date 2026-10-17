"use client";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { EmptyState } from "@/components/ui/EmptyState";
import { SeverityTag } from "@/components/ui/SeverityTag";
import { Tabs, TabPanel } from "@/components/ui/Tabs";
import { useConsole } from "@/lib/state/console-store";
import { api } from "@/lib/api/client";
import { LAYER_NAMES } from "@/lib/console-utils";
import { motion, prefersReducedMotion } from "@/lib/animations/core";
import type { ExplanationChainItem, Thresholds } from "@/lib/api/types";

export function ChainList({ chain }: { chain: ExplanationChainItem[] }) {
  const ref = useRef<HTMLOListElement>(null);
  useEffect(() => {
    const el = ref.current; if (!el || prefersReducedMotion()) return;
    const t = motion.fromTo(el.children, { opacity: 0, x: -10 }, { opacity: 1, x: 0, duration: 0.4, stagger: 0.09, ease: "expo.out" });
    return () => { t.kill(); };
  }, [chain]);
  if (!chain.length) return <p className="text-sm text-bone-3">No findings recorded.</p>;
  return (
    <ol ref={ref} className="space-y-4">
      {chain.map((c, i) => (
        <li key={i} className="relative border-l-2 border-line-strong pl-4 text-sm">
          <span aria-hidden className="absolute -left-[5px] top-1.5 size-2 bg-signal" />
          <div className="flex flex-wrap items-center gap-2">
            {c.layer && <span className="num text-signal">{String(c.layer)}</span>}
            {c.severity && <SeverityTag severity={String(c.severity)} />}
            {c.action && <span className="num text-xs text-bone-3">{String(c.action)}</span>}
          </div>
          {c.finding && <p className="mt-1.5 text-bone">{String(c.finding)}</p>}
          {c.evidence !== undefined && <p className="mt-1 break-words text-bone-2">{typeof c.evidence === "string" ? c.evidence : JSON.stringify(c.evidence)}</p>}
        </li>
      ))}
    </ol>
  );
}

function layerThreshold(t: Thresholds | null, layer: string) {
  const o = t?.[layer] as Record<string, unknown> | undefined;
  if (!o) return null;
  const pick = (x: unknown) => (x && typeof x === "object" ? (x as Record<string, number>) : null);
  const d = typeof o.warn === "number" ? (o as Record<string, number>) : pick(o.document) ?? pick(o.legacy);
  return d && typeof d.warn === "number" ? { warn: d.warn, block: d.block } : null;
}

type Tab = "chain" | "evidence" | "raw";

export function DetailPanel() {
  const eventId = useConsole((s) => s.selectedEventId);
  const events = useConsole((s) => s.events);
  const replayTs = useConsole((s) => s.replayTs);
  const [tab, setTab] = useState<Tab>("chain");
  const [th, setTh] = useState<Thresholds | null>(null);
  useEffect(() => { api.thresholds().then(setTh).catch(() => {}); }, []);

  const visible = replayTs === null ? events : events.filter((e) => e.ts <= replayTs);
  const picked = eventId ? events.find((e) => e.event_id === eventId) : undefined;
  const fallback = visible.find((e) => e.action === "BLOCKED") ?? visible[0];
  const ev = picked ?? fallback;
  if (!ev) return <EmptyState title="Nothing to inspect yet">The latest blocked event appears here as soon as one happens.</EmptyState>;
  const t = layerThreshold(th, ev.layer);
  const evidence = Object.entries(ev.evidence ?? {});

  return (
    <div className="space-y-5 p-4">
      <p className="num text-xs text-bone-3">{picked ? "Selected event" : ev.action === "BLOCKED" ? "Latest blocked event" : "Latest event"}</p>
      <div>
        <div className="flex flex-wrap items-center gap-2"><span className="num text-signal">{ev.layer}</span><span className="text-sm text-bone-2">{LAYER_NAMES[ev.layer] ?? ""}</span><SeverityTag severity={ev.severity} blocked={ev.action === "BLOCKED"} /><span className="num text-xs text-bone-3">{ev.action}</span></div>
        <h2 className="mt-2 text-xl font-semibold tracking-tight">{ev.threat_type}</h2>
        {ev.explanation?.summary && <p className="mt-1.5 text-sm text-bone-2">{ev.explanation.summary}</p>}
        <Link href={`/console/sessions/${encodeURIComponent(ev.session_id)}`} className="num mt-2 inline-block text-xs text-bone-2 underline-offset-4 hover:text-signal hover:underline">Open session {ev.session_id}</Link>
      </div>
      <div>
        <div className="flex justify-between text-sm text-bone-2"><span>Score</span><span className="num text-bone">{ev.threat_score.toFixed(3)}</span></div>
        <div className="relative mt-2 h-2 bg-ink-3">
          <div className="h-full bg-signal" style={{ width: `${Math.min(100, ev.threat_score * 100)}%` }} />
          {t && <span title={`warn ${t.warn}`} className="absolute top-[-4px] h-4 w-px bg-bone-2" style={{ left: `${t.warn * 100}%` }} />}
          {t && t.block !== undefined && <span title={`block ${t.block}`} className="absolute top-[-4px] h-4 w-px bg-bone" style={{ left: `${t.block * 100}%` }} />}
        </div>
        <p className="num mt-2 text-xs text-bone-3">{t ? `${ev.layer} warn ${t.warn.toFixed(2)}, block ${t.block?.toFixed(2)}. The score shown is on the shared axis.` : "Layer thresholds unavailable."}</p>
      </div>
      <Tabs tabs={[{ id: "chain", label: "Chain" }, { id: "evidence", label: "Evidence" }, { id: "raw", label: "Raw" }]} active={tab} onChange={(x) => setTab(x as Tab)} label="Event detail">
        <div className="pt-4">
          <TabPanel id="chain" active={tab}><ChainList chain={ev.explanation?.chain ?? []} /></TabPanel>
          <TabPanel id="evidence" active={tab}>
            {evidence.length === 0 ? <p className="text-sm text-bone-3">No evidence fields on this event.</p> : (
              <dl className="space-y-3 text-sm">{evidence.map(([k, v]) => (
                <div key={k}><dt className="num text-xs text-bone-3">{k}</dt><dd className="mt-0.5 break-words text-bone">{typeof v === "string" ? v : JSON.stringify(v)}</dd></div>
              ))}</dl>
            )}
          </TabPanel>
          <TabPanel id="raw" active={tab}><pre className="num max-h-80 overflow-auto bg-ink-0 p-3 text-xs">{JSON.stringify(ev, null, 2)}</pre></TabPanel>
        </div>
      </Tabs>
    </div>
  );
}
