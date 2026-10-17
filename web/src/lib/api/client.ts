import type { DemoList, Health, SessionState, SessionSummary, ThreatEvent, Thresholds } from "./types";

export const API_URL = (process.env.NEXT_PUBLIC_DIDA_API_URL ?? "http://localhost:8080").replace(/\/$/, "");
export const WS_URL = API_URL.replace(/^http/, "ws") + "/ws/events";

export class ApiError extends Error {
  constructor(public status: number, message: string, public body?: unknown) { super(message); this.name = "ApiError"; }
}
export class TimeoutError extends Error {
  constructor(public ms: number) { super(`The backend did not answer within ${Math.round(ms / 1000)}s. The first request after a start can be slow while models load; try again.`); this.name = "TimeoutError"; }
}
export class OfflineError extends Error {
  constructor() { super(`Backend not reachable at ${API_URL}. Start it with python main.py.`); this.name = "OfflineError"; }
}

type Opts = { method?: string; json?: unknown; form?: FormData; timeoutMs?: number; signal?: AbortSignal };

export async function request<T>(path: string, opts: Opts = {}): Promise<T> {
  const ctrl = new AbortController();
  const ms = opts.timeoutMs ?? 60000;
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; ctrl.abort(); }, ms);
  opts.signal?.addEventListener("abort", () => ctrl.abort());
  try {
    const res = await fetch(API_URL + path, {
      method: opts.method ?? (opts.json || opts.form ? "POST" : "GET"),
      headers: opts.json ? { "Content-Type": "application/json" } : undefined,
      body: opts.form ?? (opts.json ? JSON.stringify(opts.json) : undefined),
      signal: ctrl.signal,
    });
    const text = await res.text();
    let body: unknown = text;
    try { body = text ? JSON.parse(text) : null; } catch { /* keep text */ }
    if (!res.ok) {
      const detail = typeof body === "object" && body && "detail" in body ? String((body as { detail: unknown }).detail) : text || res.statusText;
      throw new ApiError(res.status, detail, body);
    }
    return body as T;
  } catch (e) {
    if (e instanceof ApiError) throw e;
    if (timedOut) throw new TimeoutError(ms);
    throw new OfflineError();
  } finally {
    clearTimeout(timer);
  }
}

export const api = {
  health: () => request<Health>("/health", { timeoutMs: 4000 }),
  thresholds: () => request<Thresholds>("/sentinel/config/thresholds"),
  demos: () => request<DemoList>("/sentinel/demo"),
  runDemo: (id: string) => request<{ status: string; scenario: string; name: string; session_id: string; layers: string[] }>(`/sentinel/demo/${encodeURIComponent(id)}`, { method: "POST" }),
  reset: () => request<{ status: string }>("/sentinel/reset", { method: "POST" }),
  events: (limit = 200) => request<ThreatEvent[]>(`/sentinel/events?limit=${limit}`),
  sessions: () => request<SessionSummary[]>("/sentinel/sessions"),
  session: (id: string) => request<SessionState>(`/sentinel/sessions/${encodeURIComponent(id)}/events`),
  l1Scan: (text: string, harmHead = true) => request<Record<string, unknown>>("/sentinel/l1/scan", { json: { text, harm_head: harmHead } }),
  ingest: (text: string, source = "playground") => request<Record<string, unknown>>("/sentinel/rag/ingest", { json: { text, source } }),
  upload: (file: File) => { const f = new FormData(); f.append("file", file); return request<Record<string, unknown>>("/sentinel/rag/upload", { form: f }); },
  toolCall: (body: Record<string, unknown>) => request<Record<string, unknown>>("/sentinel/agent/tool_call", { json: body }),
  toolResponse: (response: string, session_id?: string) => request<Record<string, unknown>>("/sentinel/agent/tool_response", { json: { response, session_id } }),
  outputScan: (response: string, system_prompt = "", session_id?: string) => request<Record<string, unknown>>("/sentinel/output/scan", { json: { response, system_prompt, session_id } }),
  chat: (message: string, session_id?: string) => request<Record<string, unknown>>("/sentinel/chat", { json: { content: message, session_id }, timeoutMs: 60000 }),
  scanImage: (file: File) => { const f = new FormData(); f.append("file", file); return request<Record<string, unknown>>("/sentinel/l1/scan-image", { form: f }); },
};
