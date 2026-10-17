/**
 * The only place numbers live. Every fact carries a `source`: the README / results.md
 * section it was copied from. Components import by key and render a SourceNote.
 */
export type Fact = { value: number; display: string; label: string; source: string };

const f = (value: number, display: string, label: string, source: string): Fact => ({ value, display, label, source });

export const FACTS = {
  // Live AgentDojo agent: attack success / utility under attack / benign utility
  "live.none.asr": f(0.588, "0.588", "Attack success, no defense", "README, Results, AgentDojo"),
  "live.none.utilAttack": f(0.529, "0.529", "Task success under attack, no defense", "README, Results, AgentDojo"),
  "live.none.utilBenign": f(0.853, "0.853", "Task success without attack, no defense", "README, Results, AgentDojo"),
  "live.detector.asr": f(0.015, "0.015", "Attack success, AgentDojo detector", "README, Results, AgentDojo"),
  "live.detector.utilAttack": f(0.206, "0.206", "Task success under attack, AgentDojo detector", "README, Results, AgentDojo"),
  "live.detector.utilBenign": f(0.471, "0.471", "Task success without attack, AgentDojo detector", "README, Results, AgentDojo"),
  "live.l4.asr": f(0.103, "0.103", "Attack success, DIDA tool-call check", "README, Results, AgentDojo"),
  "live.l4.utilAttack": f(0.574, "0.574", "Task success under attack, DIDA tool-call check", "README, Results, AgentDojo"),
  "live.l4.utilBenign": f(0.853, "0.853", "Task success without attack, DIDA tool-call check", "README, Results, AgentDojo"),
  "live.full.asr": f(0.044, "0.044", "Attack success, DIDA full", "README, Results, AgentDojo"),
  "live.full.utilAttack": f(0.309, "0.309", "Task success under attack, DIDA full", "README, Results, AgentDojo"),
  "live.full.utilBenign": f(0.794, "0.794", "Task success without attack, DIDA full", "README, Results, AgentDojo"),
  "live.detector.broken": f(13, "13 of 34", "Benign tasks broken by the AgentDojo detector", "README, Results, AgentDojo"),
  "live.full.stopped": f(37, "37", "Attacks stopped by DIDA full, none enabled", "README, Results, AgentDojo"),

  // Per-layer benchmarks
  "l1h.wjb.auroc": f(0.952, "0.952", "WildJailbreak AUROC", "README, Every layer"),
  "l3.tomgibbs.auroc": f(0.996, "0.996", "Cipher jailbreak AUROC, tom-gibbs", "README, Every layer"),
  "l4.injecagent.recall": f(1.0, "1.000", "InjecAgent recall, zero false positives", "README, Every layer"),
  "pipeline.blocked": f(91.5, "91.5%", "DIDA-Bench attacks blocked, zero false positives", "README, Every layer"),
  "l2.bipia.auroc": f(0.928, "0.928", "BIPIA AUROC", "README, Every layer"),
  "l5.agentleak.auroc": f(0.888, "0.888", "AgentLeak AUROC", "README, Every layer"),
  "l1.tensortrust.recall": f(0.875, "0.875", "TensorTrust recall", "README, Every layer"),

  // Research
  "research.blind": f(0, "0", "Correlation engine detections on 510 certified sub-threshold attacks", "README, Research finding 1"),
  "research.jaccard": f(1.0, "1.0000", "Jaccard between the valid e-process and the best single layer", "README, Research finding 3"),
  "research.capacity.low": f(66.7, "66.7%", "Undefended headroom, low end", "README, Research finding 6"),
  "research.capacity.high": f(85.2, "85.2%", "Undefended headroom, high end", "README, Research finding 6"),
  "research.capacity.stack2": f(37.4, "37.4%", "Undefended headroom on the third-party stack", "README, Research finding 6"),
  "research.capacity.accept": f(3.002, "3.002", "Largest attack budget that fits under every threshold", "README, Contribution H"),
  "research.capacity.reject": f(3.04, "3.040", "First budget that does not fit", "README, Contribution H"),
  "research.splitS2": f(447, "447", "SPLIT-S2 sessions against the third-party stack", "README, Contribution G"),
  "research.splitV1": f(680, "680", "SPLIT-Bench v1 sessions", "README, Contribution G"),
  "research.splitV2": f(510, "510", "SPLIT-Bench v2 sessions", "README, Contribution G"),
  "research.hardened": f(0, "0 of 4,080", "Three-layer attacks certifiable after hardening", "README, Contribution G"),
  "research.conformal.target": f(1, "1%", "Conformal false-positive target", "README, Contribution D"),
  "research.conformal.shift": f(14.8, "14.8%", "False positives under shift, WildJailbreak benign set", "README, Contribution D"),
  "research.triage.layers": f(3.4, "~3.4 of 5", "Layers used before an attack is decided", "README, Contribution B"),
} as const satisfies Record<string, Fact>;

export type FactKey = keyof typeof FACTS;
export const fact = (k: FactKey) => FACTS[k];

/** Live agent comparison rows, in presentation order. */
export const LIVE_ROWS = [
  { id: "none", name: "No defense", asr: "live.none.asr", util: "live.none.utilBenign" },
  { id: "detector", name: "AgentDojo detector", asr: "live.detector.asr", util: "live.detector.utilBenign" },
  { id: "l4", name: "DIDA, tool-call check", asr: "live.l4.asr", util: "live.l4.utilBenign" },
  { id: "full", name: "DIDA, full", asr: "live.full.asr", util: "live.full.utilBenign" },
] as const satisfies readonly { id: string; name: string; asr: FactKey; util: FactKey }[];

/** Before and after table (README, What the engineering bought). */
export const ENGINEERING = [
  { problem: "Harmful intent hidden in roleplay (WildJailbreak AUROC)", before: "0.574", after: "0.952" },
  { problem: "Cipher-encoded multi-turn jailbreaks (tom-gibbs AUROC / FPR)", before: "0.755 / 10.2%", after: "0.996 / 0%" },
  { problem: "Poisoned documents (BIPIA AUROC)", before: "0.719", after: "0.928" },
  { problem: "Poisoned documents (BIPIA held-out recall @ FPR)", before: "0.148 @ 4.0%", after: "0.636 @ 1.3%" },
  { problem: "Agent hijacking, trace replay (attack execution per suite)", before: "0.59 / 1.00 / 0.45 / 0.41", after: "0.00 / 0.20 / 0.02 / 0.00" },
  { problem: "Tool-call false alarms on benign agent traffic", before: "56% of calls", after: "2 to 20% by suite" },
  { problem: "Injection false positives on trigger-word prompts (NotInject)", before: "11.5%", after: "3.2% (judge off)" },
  { problem: "Full-pipeline blocking on DIDA-Bench (0 false positives)", before: "69.5%", after: "91.5%" },
] as const;

/** Third-party comparison (README, Against third-party guards). */
export const GUARDS = {
  columns: ["Llama Guard 3 (1B)", "ProtectAI DeBERTa v2", "DIDA"],
  rows: [
    { metric: "WildJailbreak AUROC", values: ["0.814", "0.653", "0.952"], best: 2 },
    { metric: "Multi-turn attacks (MHJ vs. real chats), AUROC", values: ["0.682", "0.566", "0.682 (L3); 0.954 (probe, not shipped)"], best: 2 },
    { metric: "Certified sub-threshold sessions caught (SPLIT-Bench v1)", values: ["1 / 340", "0 / 340", "265 / 340 (L3)"], best: 2 },
    { metric: "TensorTrust recall", values: ["0.588", "0.970", "0.875"], best: 1 },
    { metric: "False positives on NotInject", values: ["7.4%", "43.4%", "3.5%"], best: 2 },
  ],
} as const;
