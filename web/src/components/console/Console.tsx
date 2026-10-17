"use client";
import { useEffect, useRef, useState } from "react";
import { TopBar } from "./TopBar";
import { EventStream } from "./EventStream";
import { SessionList } from "./SessionList";
import { DetailPanel } from "./DetailPanel";
import { Radar } from "./Radar";
import { Timeline } from "./Timeline";
import { LayerSparks } from "./LayerSparks";
import { MobileConsole } from "./MobileConsole";
import { ChatPanel } from "./ChatPanel";
import { useIsDesktop } from "@/hooks/useIsDesktop";
import { Tabs, TabPanel } from "@/components/ui/Tabs";
import { InlineError } from "@/components/ui/InlineError";
import { connectEvents } from "@/lib/api/socket";
import { api, API_URL } from "@/lib/api/client";
import { useConsole } from "@/lib/state/console-store";
import clsx from "clsx";

export function Console() {
  const { ingest, setConnection, hydrate } = useConsole.getState();
  const conn = useConsole((s) => s.connection);
  const events = useConsole((s) => s.events);
  const replayTs = useConsole((s) => s.replayTs);
  const setReplay = useConsole((s) => s.setReplayTs);
  const desktop = useIsDesktop();
  const [left, setLeft] = useState<"stream" | "sessions" | "chat">("stream");
  const [mobile, setMobile] = useState<"feed" | "detail">("feed");
  const [scripted, setScripted] = useState<Set<string>>(new Set());
  const [announce, setAnnounce] = useState("");
  const lastAnnounce = useRef(0);
  const prevBlocked = useRef(0);
  const replayRef = useRef<number | null>(null); replayRef.current = replayTs;
  const clock = useRef(() => replayRef.current ?? Date.now() / 1000).current;

  useEffect(() => {
    const stop = connectEvents({
      onMessage: ingest,
      onState: (s, retry) => {
        setConnection(s, retry);
        if (s === "live") Promise.all([api.events(300), api.sessions()]).then(([e, ss]) => hydrate(e, ss)).catch(() => {});
      },
    });
    return stop;
  }, [ingest, setConnection, hydrate]);

  useEffect(() => {
    try {
      const d = localStorage.getItem("dida.density"); if (d === "compact" || d === "comfortable") useConsole.getState().setDensity(d);
      if (localStorage.getItem("dida.grouped") === "1") useConsole.getState().setGrouped(true);
    } catch { /* storage unavailable */ }
  }, []);

  useEffect(() => useConsole.subscribe((st) => {
    if (st.stats.blocked > prevBlocked.current && Date.now() - lastAnnounce.current > 5000) { lastAnnounce.current = Date.now(); setAnnounce(`${st.stats.blocked} events blocked`); }
    prevBlocked.current = st.stats.blocked;
  }), []);

  const visible = replayTs === null ? events : events.filter((e) => e.ts <= replayTs);
  const dead = conn === "disconnected";
  const ago = replayTs === null ? 0 : Math.max(0, Math.round(Date.now() / 1000 - replayTs));

  return (
    <div className="flex h-dvh min-h-0 flex-col bg-ink-0">
      <TopBar onScenario={(sid) => setScripted((s) => new Set(s).add(sid))} />
      {dead && <div className="border-b border-line p-3"><InlineError title="Backend offline">{`Not reachable at ${API_URL}. Start it with python main.py. The console reconnects on its own.`}</InlineError></div>}

      {!desktop ? <MobileConsole events={visible} clock={clock} dead={dead} scripted={scripted} /> : (
      <main id="main" tabIndex={-1} className="grid min-h-0 flex-1 grid-rows-[auto_minmax(0,1fr)] gap-2 p-2 lg:grid-cols-[23rem_minmax(0,1fr)_23rem] lg:grid-rows-1">
        {/* radar + timeline: the centrepiece; on small screens it sits on top */}
        <section aria-label="Live radar" className="flex min-h-0 flex-col gap-2 lg:order-2">
          <div className="surface-1 relative h-60 min-h-0 overflow-hidden lg:h-auto lg:flex-1">
            <Radar events={visible} clock={clock} frozen={dead} className="absolute inset-0" />
            <div className="pointer-events-none absolute left-3 top-3 flex items-center gap-2 text-xs">
              {replayTs !== null
                ? <span className="num rounded-full bg-signal px-3 py-1 font-medium text-ink-0">Replay · {ago}s ago</span>
                : <span className="num text-bone-3">{dead ? "Disconnected" : conn === "connecting" ? "Connecting" : "Lights only on real events"}</span>}
            </div>
            {replayTs !== null && <button onClick={() => setReplay(null)} className="absolute right-3 top-3 rounded-full border border-line-strong bg-ink-1 px-3 py-1 text-xs text-bone hover:bg-ink-3">Back to live</button>}
          </div>
          <div className="hidden lg:block"><LayerSparks /></div>
          <div className="hidden lg:block"><Timeline /></div>
        </section>

        <div className="grid min-h-0 gap-2 lg:contents">
          <div role="tablist" aria-label="Console view" className="flex border-b border-line lg:hidden">
            {(["feed", "detail"] as const).map((p) => <button key={p} role="tab" aria-selected={mobile === p} onClick={() => setMobile(p)} className={clsx("h-11 flex-1 text-sm", mobile === p ? "border-b-2 border-signal text-bone" : "text-bone-3")}>{p === "feed" ? "Feed" : "Detail"}</button>)}
          </div>
          <section aria-label="Event feed" className={clsx("surface-1 min-h-0 flex-col overflow-hidden lg:order-1 lg:flex", mobile === "feed" ? "flex" : "hidden")}>
            <Tabs tabs={[{ id: "stream", label: "Stream" }, { id: "sessions", label: "Sessions" }, { id: "chat", label: "Chat" }]} active={left} onChange={(x) => setLeft(x as "stream" | "sessions" | "chat")} label="Feed" className="flex min-h-0 flex-1 flex-col">
              <TabPanel id="stream" active={left} className="min-h-0 flex-1"><EventStream scripted={scripted} /></TabPanel>
              <TabPanel id="sessions" active={left} className="pane-scroll min-h-0 flex-1 overflow-auto"><SessionList /></TabPanel>
              <TabPanel id="chat" active={left} className="min-h-0 flex-1"><ChatPanel /></TabPanel>
            </Tabs>
          </section>
          <section aria-label="Inspector" className={clsx("surface-1 pane-scroll min-h-0 overflow-auto lg:order-3 lg:block", mobile === "detail" ? "block" : "hidden")}><DetailPanel /></section>
        </div>
      </main>)}
      <p className="sr-only-text" role="status" aria-live="polite">{announce}</p>
    </div>
  );
}
