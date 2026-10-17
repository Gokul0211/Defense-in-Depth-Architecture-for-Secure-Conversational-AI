import { create } from "zustand";
import type { ConnectionState, SessionState, SessionSummary, Stats, ThreatEvent, WsMessage } from "@/lib/api/types";

const RING = 1000;
const EMPTY: Stats = { active_sessions: 0, blocked: 0, counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }, layer_scores: { L1: 0, L2: 0, L3: 0, L4: 0, L5: 0 } };

type Store = {
  events: ThreatEvent[];           // newest first, ring buffer of 1,000
  sessions: Record<string, SessionSummary>;
  stats: Stats;
  connection: ConnectionState;
  retryAt: number | null;
  selectedEventId: string | null;
  selectedSessionId: string | null;
  replayTs: number | null;         // seconds; null means live
  filters: { layer: string; severity: string; action: string };
  setFilters: (f: Partial<{ layer: string; severity: string; action: string }>) => void;
  setReplayTs: (t: number | null) => void;
  density: "comfortable" | "compact";
  grouped: boolean;
  setDensity: (d: "comfortable" | "compact") => void;
  setGrouped: (g: boolean) => void;
  lastEvent: ThreatEvent | null;   // drives the live labyrinth
  ingest: (m: WsMessage) => void;
  hydrate: (events: ThreatEvent[], sessions: SessionSummary[]) => void;
  setConnection: (c: ConnectionState, retryInMs?: number) => void;
  selectEvent: (id: string | null) => void;
  selectSession: (id: string | null) => void;
};

const summarize = (s: SessionState): SessionSummary => ({
  session_id: s.session_id, risk: s.risk, overall: s.overall, turn_count: s.turn_count,
  event_count: s.events.length, last_event_ts: s.events.at(-1)?.ts ?? null,
  terminated: s.terminated, termination_reason: s.termination_reason,
});

export const useConsole = create<Store>((set) => ({
  events: [], sessions: {}, stats: EMPTY, connection: "connecting", retryAt: null,
  selectedEventId: null, selectedSessionId: null, lastEvent: null, replayTs: null,
  filters: { layer: "", severity: "", action: "" },
  setFilters: (f) => set((st) => ({ filters: { ...st.filters, ...f } })),
  setReplayTs: (replayTs) => set({ replayTs }),
  density: "comfortable", grouped: false,
  setDensity: (density) => { try { localStorage.setItem("dida.density", density); } catch { /* storage unavailable */ } set({ density }); },
  setGrouped: (grouped) => { try { localStorage.setItem("dida.grouped", grouped ? "1" : "0"); } catch { /* storage unavailable */ } set({ grouped }); },
  ingest: (m) => set((st) => {
    switch (m.type) {
      case "THREAT_EVENT": {
        if (st.events.some((e) => e.event_id === m.payload.event_id)) return st;
        return { events: [m.payload, ...st.events].slice(0, RING), lastEvent: m.payload };
      }
      case "SESSION_UPDATE": return { sessions: { ...st.sessions, [m.payload.session_id]: summarize(m.payload) } };
      case "STATS_UPDATE": return { stats: m.payload };
      case "RESET": return { replayTs: null, events: [], sessions: {}, stats: m.payload ?? EMPTY, selectedEventId: null, selectedSessionId: null, lastEvent: null };
      default: return st;
    }
  }),
  hydrate: (events, sessions) => set((st) => {
    const known = new Set(st.events.map((e) => e.event_id));
    const merged = [...st.events, ...[...events].reverse().filter((e) => !known.has(e.event_id))]
      .sort((a, b) => b.ts - a.ts).slice(0, RING);
    return { events: merged, sessions: { ...Object.fromEntries(sessions.map((s) => [s.session_id, s])), ...st.sessions } };
  }),
  setConnection: (connection, retryInMs) => set({ connection, retryAt: retryInMs ? Date.now() + retryInMs : null }),
  selectEvent: (id) => set((st) => ({ selectedEventId: id, selectedSessionId: id ? st.events.find((e) => e.event_id === id)?.session_id ?? st.selectedSessionId : st.selectedSessionId })),
  selectSession: (id) => set({ selectedSessionId: id, selectedEventId: null }),
}));
