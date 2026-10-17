import type { Thresholds } from "@/lib/api/types";

/** Turns the different endpoint responses into one verdict shape for the Playground. */
export type Tool = "l1" | "chat" | "ingest" | "toolcall" | "toolresp" | "output" | "image";
export interface Verdict { decision: "ALLOWED" | "WARNED" | "BLOCKED"; score: number | null; reason: string; stopLayer: string | null; text?: string; raw: unknown }

type R = Record<string, unknown>;
const num = (x: unknown): number | null => (typeof x === "number" ? x : null);
const str = (x: unknown): string => (typeof x === "string" ? x : "");

/** The layer that decided: the first chain entry, skipping the evidence-bus summary the backend appends on a block. */
function stopLayerOf(res: R): string | null {
  const chain = (res.explanation as { chain?: { layer?: unknown }[] } | undefined)?.chain;
  const l = chain?.find((c) => typeof c.layer === "string" && c.layer !== "TIB")?.layer ?? chain?.find((c) => typeof c.layer === "string")?.layer;
  return typeof l === "string" ? l.slice(0, 2) : null;
}

const limit = (t: Thresholds | null | undefined, layer: string, key: "warn" | "block", fallback: number): number => {
  const v = (t?.[layer] as Record<string, unknown> | undefined)?.[key];
  return typeof v === "number" ? v : fallback;
};

/** Pass the backend's live thresholds so WARN/BLOCK match the layer's own operating point. */
export function toVerdict(tool: Tool, res: R, th?: Thresholds | null): Verdict {
  switch (tool) {
    case "l1": {
      const l1 = (res.l1 ?? {}) as R; const a = str(res.action);
      return { decision: a === "BLOCKED" ? "BLOCKED" : a === "WARNED" ? "WARNED" : "ALLOWED", score: num(l1.score), reason: str(l1.reason), stopLayer: a === "BLOCKED" || a === "WARNED" ? "L1" : null, raw: res };
    }
    case "chat": {
      const action = str(res.action);
      return { decision: res.blocked ? "BLOCKED" : action === "WARNED" ? "WARNED" : "ALLOWED", score: num(res.threat_score), reason: str((res.explanation as R | undefined)?.summary) || (res.blocked ? "Blocked." : "Passed every layer."), stopLayer: res.blocked ? stopLayerOf(res) : null, text: str(res.response), raw: res };
    }
    case "ingest": {
      const { embedding: _e, text: _t, ...rest } = res; void _e; void _t;
      const meta = (res.metadata ?? {}) as R; const dt = (meta.document_threat ?? {}) as R;
      const score = dt.available === false ? null : num(dt.threat);
      return { decision: res.quarantined ? "BLOCKED" : res.review_flagged ? "WARNED" : "ALLOWED", score, reason: str(res.reason), stopLayer: res.quarantined || res.review_flagged ? "L2" : null, raw: rest };
    }
    case "toolcall": {
      const score = num(res.score);
      const warned = res.should_execute === true && score !== null && score >= limit(th, "L4", "warn", 0.7);
      return { decision: res.should_execute ? (warned ? "WARNED" : "ALLOWED") : "BLOCKED", score, reason: str(res.reason), stopLayer: res.should_execute && !warned ? null : "L4", raw: res };
    }
    case "toolresp":
      return { decision: res.blocked ? "BLOCKED" : "ALLOWED", score: num(res.score), reason: str(res.reason), stopLayer: res.blocked ? "L4" : null, raw: res };
    case "output": {
      const r = (res.result ?? {}) as R; const s = num(r.score);
      const warn = limit(th, "L5", "warn", 0.5), block = limit(th, "L5", "block", 0.85);
      return { decision: s !== null && s >= block ? "BLOCKED" : s !== null && s >= warn ? "WARNED" : "ALLOWED", score: s, reason: str(r.reason), stopLayer: s !== null && s >= warn ? "L5" : null, text: str(res.sanitized_response) || undefined, raw: res };
    }
    case "image": {
      const flagged = res.blocked === true || res.is_malicious === true;
      const score = Math.max(num(res.l1_score) ?? 0, num(res.chi_score) ?? 0);
      return { decision: flagged ? "BLOCKED" : "ALLOWED", score, reason: str(res.reason), stopLayer: flagged ? "L1" : null, raw: res };
    }
  }
}

export const TOOL_LAYERS: Record<Tool, string[]> = {
  l1: ["L1"], chat: ["L1", "L2", "L3", "L4", "L5"], ingest: ["L2"], toolcall: ["L4"], toolresp: ["L4"], output: ["L5"], image: ["L1"],
};
