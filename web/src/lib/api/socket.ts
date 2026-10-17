import { WS_URL } from "./client";
import type { WsMessage } from "./types";

type Handlers = {
  onMessage: (m: WsMessage) => void;
  onState: (s: "connecting" | "live" | "disconnected", retryInMs?: number) => void;
};

/** One WebSocket per tab: exponential backoff 1s to 30s, parse by `type`, silence watchdog. */
export function connectEvents({ onMessage, onState }: Handlers): () => void {
  let ws: WebSocket | null = null;
  let stopped = false;
  let attempt = 0;
  let retryTimer: ReturnType<typeof setTimeout> | undefined;

  const open = () => {
    if (stopped) return;
    onState("connecting");
    try { ws = new WebSocket(WS_URL); } catch { schedule(); return; }
    ws.onopen = () => { attempt = 0; onState("live"); };
    ws.onmessage = (e) => {
      try {
        const m = JSON.parse(String(e.data)) as WsMessage;
        if (m && typeof m.type === "string") onMessage(m);
      } catch { /* ignore malformed frame */ }
    };
    ws.onclose = () => { ws = null; if (!stopped) schedule(); };
    ws.onerror = () => { ws?.close(); };
  };

  const schedule = () => {
    const delay = Math.min(30000, 1000 * 2 ** attempt++);
    onState("disconnected", delay);
    retryTimer = setTimeout(open, delay);
  };

  open();
  return () => { stopped = true; clearTimeout(retryTimer); ws?.close(); };
}
