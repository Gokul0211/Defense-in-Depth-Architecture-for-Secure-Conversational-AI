import type { ThreatEvent } from "@/lib/api/types";

export const RING: Record<string, number> = { L1: 0, L2: 1, L3: 2, L4: 3, L5: 4 };
export const LAYER_NAMES: Record<string, string> = { L1: "Input", L2: "Documents", L3: "Conversation", L4: "Tool calls", L5: "Output", TIB: "Evidence bus" };

/** Stable 0..1 hash so a session always lands at the same angle on the radar. */
export function hash01(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return ((h >>> 0) % 100000) / 100000;
}

export const isHot = (e: ThreatEvent) => e.action === "BLOCKED" || e.severity === "CRITICAL" || e.severity === "HIGH";

/** First useful line of explanation for a row. */
export function reasonOf(e: ThreatEvent): string {
  const first = e.explanation?.chain?.find((c) => typeof c.finding === "string" && c.finding)?.finding;
  return String(e.explanation?.summary || first || e.note || "").trim();
}
