import { create } from "zustand";
import { api, ApiError, OfflineError, TimeoutError } from "@/lib/api/client";
import type { ChatResult, ChatStage } from "@/lib/api/types";

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
}));
