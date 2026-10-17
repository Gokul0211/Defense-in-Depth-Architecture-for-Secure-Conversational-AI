export type LayerId = "L1" | "L2" | "L3" | "L4" | "L5" | "TIB";

export const LAYERS: {
  id: LayerId; wall: number | null; name: string; stops: string; blurb: string;
  metric: { label: string; value: string; source: string };
}[] = [
  {
    id: "L1", wall: 0, name: "Input", stops: "Prompt injection and jailbreak framing",
    blurb: "Regex, semantic templates, then Prompt Guard and PIGuard together. A separate head scores harmful intent.",
    metric: { label: "TensorTrust recall", value: "0.875", source: "README, Every layer" },
  },
  {
    id: "L2", wall: 1, name: "Documents", stops: "Poisoned retrieval and tool outputs",
    blurb: "Each content type gets its own conformal anchor, so news, code and tool output are judged on their own terms.",
    metric: { label: "BIPIA AUROC", value: "0.928", source: "README, Every layer" },
  },
  {
    id: "L3", wall: 2, name: "Conversation", stops: "Slow escalation and cipher jailbreaks",
    blurb: "Tracks drift and velocity across the session. Once a cipher is declared, it scores the decoded goal.",
    metric: { label: "Cipher jailbreak AUROC", value: "0.996", source: "README, Every layer" },
  },
  {
    id: "L4", wall: 3, name: "Tool calls", stops: "Agent hijacking",
    blurb: "The user must have asked for the action, and every argument is traced to its source. Text talking to the model is flagged.",
    metric: { label: "InjecAgent recall", value: "1.000", source: "README, Every layer" },
  },
  {
    id: "L5", wall: 4, name: "Output", stops: "Data leakage",
    blurb: "PII and exfiltration patterns, canary tokens including base64, and a provenance check on free text.",
    metric: { label: "AgentLeak AUROC", value: "0.888", source: "README, Every layer" },
  },
  {
    id: "TIB", wall: null, name: "Evidence bus", stops: "Everything the layers see, per session",
    blurb: "A shared per-session bus feeds four correlation rules and a taint graph. A block verdict ends the session.",
    metric: { label: "Correlation rules", value: "4", source: "FRONTEND_SPEC, 3.1" },
  },
];

export const SEVERITIES = ["CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
export type Severity = (typeof SEVERITIES)[number];
