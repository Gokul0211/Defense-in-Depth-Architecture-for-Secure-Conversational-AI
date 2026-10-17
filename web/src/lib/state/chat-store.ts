import { create } from "zustand";
import { api, ApiError, OfflineError, TimeoutError } from "@/lib/api/client";
import type { ChatResult, ChatStage, KbChunk } from "@/lib/api/types";

export interface ChatMsg {
  id: string;
  role: "user" | "assistant";
  text: string;
  result?: ChatResult;
  error?: boolean;
}

export type ChatPhase = "idle" | "running" | "done";

type ChatStore = {
  sessionId: string;
  messages: ChatMsg[];
  phase: ChatPhase;
  /** Stage verdicts of the latest message, for the pipeline strip. */
  stages: ChatStage[] | null;
  last: ChatResult | null;
  send: (text: string) => Promise<void>;
  newChat: () => void;
  /** The knowledge base the chat retrieves from. It lives on the backend and is shared by every session. */
  kb: KbChunk[];
  kbBusy: boolean;
  kbNote: { tone: "ok" | "hot" | "error"; text: string } | null;
  refreshKb: () => Promise<void>;
  addDoc: (text: string, source: string) => Promise<void>;
  addPdf: (file: File) => Promise<void>;
  tamper: (chunkId: string) => Promise<void>;
};

const newId = () => Math.random().toString(36).slice(2, 10);
const newSession = () => `chat_${newId()}`;

const errorText = (e: unknown): string =>
  e instanceof ApiError ? `${e.message} (HTTP ${e.status})`
    : e instanceof OfflineError || e instanceof TimeoutError ? e.message
      : e instanceof Error ? e.message : "Request failed.";

/** One conversation, kept outside the component so it survives switching console tabs. */
export const useChat = create<ChatStore>((set, get) => ({
  sessionId: newSession(),
  messages: [],
  phase: "idle",
  stages: null,
  last: null,
  send: async (raw) => {
    const text = raw.trim();
    if (!text || get().phase === "running") return;
    const sid = get().sessionId;
    set((s) => ({ messages: [...s.messages, { id: newId(), role: "user", text }], phase: "running", stages: null, last: null }));
    try {
      const r = await api.chat(text, sid);
      if (get().sessionId !== sid) return; // the user started a new chat while this one was in flight
      set((s) => ({
        messages: [...s.messages, { id: newId(), role: "assistant", text: r.response, result: r }],
        phase: "done", stages: r.stages, last: r,
      }));
    } catch (e) {
      if (get().sessionId !== sid) return;
      set((s) => ({ messages: [...s.messages, { id: newId(), role: "assistant", text: errorText(e), error: true }], phase: "idle", stages: null, last: null }));
    }
  },
  newChat: () => set({ sessionId: newSession(), messages: [], phase: "idle", stages: null, last: null }),

  kb: [],
  kbBusy: false,
  kbNote: null,
  refreshKb: async () => {
    try { const r = await api.ragChunks(); set({ kb: r.chunks }); } catch (e) { set({ kbNote: { tone: "error", text: errorText(e) } }); }
  },
  addDoc: async (text, source) => {
    if (!text.trim() || get().kbBusy) return;
    set({ kbBusy: true, kbNote: null });
    try {
      const r = await api.ingest(text, source) as { quarantined?: boolean; review_flagged?: boolean; reason?: string };
      set({ kbNote: r.quarantined ? { tone: "hot", text: `Quarantined, so the model will never see it. ${r.reason ?? ""}` }
        : r.review_flagged ? { tone: "hot", text: `Held for review, so it is not retrievable. ${r.reason ?? ""}` }
          : { tone: "ok", text: "Admitted. Questions that match it will now retrieve it." } });
    } catch (e) { set({ kbNote: { tone: "error", text: errorText(e) } }); }
    await get().refreshKb();
    set({ kbBusy: false });
  },
  addPdf: async (file) => {
    if (get().kbBusy) return;
    set({ kbBusy: true, kbNote: null });
    try {
      const r = await api.upload(file) as { chunks_ingested?: number; chunks_quarantined?: number; chunks_review_flagged?: number };
      const q = r.chunks_quarantined ?? 0, f = r.chunks_review_flagged ?? 0;
      set({ kbNote: { tone: q || f ? "hot" : "ok", text: `${r.chunks_ingested ?? 0} chunks scored: ${(r.chunks_ingested ?? 0) - q - f} admitted, ${q} quarantined, ${f} held for review.` } });
    } catch (e) { set({ kbNote: { tone: "error", text: errorText(e) } }); }
    await get().refreshKb();
    set({ kbBusy: false });
  },
  tamper: async (chunkId) => {
    set({ kbBusy: true, kbNote: null });
    try {
      await api.tamper(chunkId);
      set({ kbNote: { tone: "hot", text: "The stored text was edited. Its signature no longer matches, so retrieval will quarantine it. Ask a question that matches it." } });
    } catch (e) { set({ kbNote: { tone: "error", text: errorText(e) } }); }
    await get().refreshKb();
    set({ kbBusy: false });
  },
}));
