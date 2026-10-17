/** Mirrors sentinel/core/models.py and the payloads in sentinel/app.py. */
export type LayerKey = "L1" | "L2" | "L3" | "L4" | "L5" | "TIB";
export type SeverityKey = "CLEAN" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type ActionKey = "ALLOWED" | "WARNED" | "BLOCKED";

export interface ExplanationChainItem {
  layer?: string;
  severity?: string;
  finding?: string;
  evidence?: string | Record<string, unknown>;
  action?: string;
  [k: string]: unknown;
}

export interface ThreatEvent {
  event_id: string;
  timestamp: string;
  ts: number;
  session_id: string;
  layer: LayerKey | string;
  threat_type: string;
  severity: SeverityKey | string;
  threat_score: number;
  action: ActionKey | string;
  evidence: Record<string, unknown>;
  explanation: { summary?: string; chain?: ExplanationChainItem[] };
  turn: number | null;
  note: string | null;
}

export interface Turn { turn_number: number; score: number; severity: string; note: string; layer: string }

export interface SessionState {
  session_id: string;
  turn_count: number;
  turns: Turn[];
  events: ThreatEvent[];
  l1_max: number;
  l2_findings: unknown[];
  l2_flagged_chunks: unknown[];
  l3_current: number;
  l4_calls: Record<string, unknown>[];
  l5_scores: unknown[];
  overall: number;
  risk: string;
  chat_history: unknown[];
  turn_provenance: unknown[];
  tracked_sensitive_values: unknown[];
  terminated: boolean;
  termination_reason: string;
}

export interface SessionSummary {
  session_id: string;
  risk: string;
  overall: number;
  turn_count: number;
  event_count: number;
  last_event_ts: number | null;
  terminated: boolean;
  termination_reason: string;
}

export interface Stats {
  active_sessions: number;
  blocked: number;
  counts: Record<string, number>;
  layer_scores: Record<string, number>;
}

export type WsMessage =
  | { type: "STATS_UPDATE"; payload: Stats }
  | { type: "THREAT_EVENT"; payload: ThreatEvent }
  | { type: "SESSION_UPDATE"; payload: SessionState }
  | { type: "CHAT_MESSAGE"; payload: Record<string, unknown> }
  | { type: "RESET"; payload: Stats };

export interface Health {
  status: string;
  service: string;
  version: string;
  capabilities: { llm_chat: boolean; l1_judge: boolean; image_scan: boolean };
}

export type Thresholds = Record<string, Record<string, unknown>>;

export interface DemoScenario {
  id: string;
  name: string;
  /** The backend sends the one-line summary as `desc`. */
  desc?: string;
  description?: string;
  layers?: string[];
  source?: string | null;
  sample_id?: string | null;
  scripted: string[];
  approximations: string[];
  [k: string]: unknown;
}
export interface DemoList { cooldown_seconds: number; scenarios: DemoScenario[] }

export type ConnectionState = "connecting" | "live" | "disconnected";
