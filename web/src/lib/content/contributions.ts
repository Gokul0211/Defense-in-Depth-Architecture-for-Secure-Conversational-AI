export type Contribution = {
  id: "A" | "B" | "C" | "D" | "E" | "F" | "G" | "H";
  name: string; truth: string; weight: string; code: string;
};

export const CONTRIBUTIONS: Record<Contribution["id"], Contribution> = {
  A: { id: "A", name: "Taint-propagation graph", truth: "Turns a session into a provenance graph and propagates trust along it. Flags high-impact calls fed by low-trust content.", weight: "Generalizes one hand-coded rule. 0 unique detections.", code: "sentinel/core/taint_graph.py" },
  B: { id: "B", name: "Cost-aware sequential triage", truth: "Runs layers as a Wald sequential test and stops when the evidence is decisive.", weight: "Earlier configuration. Saves cost on attacks only.", code: "sentinel/core/sequential_triage.py" },
  C: { id: "C", name: "Correlation-pattern mining", truth: "Mines attack-chain patterns from labeled cross-layer sequences instead of hand-writing rules.", weight: "Collapses to L3 alone on certified attacks.", code: "sentinel/core/pattern_mining.py" },
  D: { id: "D", name: "Conformal risk control", truth: "Sets each threshold by split-conformal calibration on benign data, for a distribution-free false-positive guarantee.", weight: "Shown to break under shift: 14.8% against a 1% target.", code: "sentinel/core/conformal_risk_control.py" },
  E: { id: "E", name: "Detectability bound", truth: "Any detector that reads only threshold crossings has zero power against an attacker who keeps every layer under its threshold.", weight: "The theory backbone.", code: "SENTINEL_CONTRIBUTION_E_THEORY.md" },
  F: { id: "F", name: "Anytime-valid e-value fusion", truth: "Fuses layer scores across layers and turns. False alarms stay controlled under any dependence.", weight: "Matches the best single layer exactly. An important negative result.", code: "sentinel/core/evidence_fusion.py" },
  G: { id: "G", name: "SPLIT-Bench", truth: "Attack sessions with a machine-checked certificate that every layer stays under its threshold while at least k carry signal.", weight: "The most original artifact.", code: "sentinel/eval/split_bench.py" },
  H: { id: "H", name: "Threshold-aware adversary", truth: "Models the attacker who knows every threshold and computes how much attack signal the stack lets them hide.", weight: "A new practical metric: effective capacity.", code: "sentinel/eval/split_attack.py" },
};

/** Presentation order: the kit first, then the four mechanisms and where each stops. */
export const KIT_ORDER = ["E", "G", "H", "F"] as const;
export const MECHANISM_ORDER = ["A", "B", "C", "D"] as const;

export const FINDINGS = [
  { n: 1, title: "Threshold fusion is provably blind to a sub-threshold attacker", evidence: "The correlation engine fired 0 times on SPLIT-Bench v1 (680 sessions) and v2 (510), whose sessions carry machine-checked sub-threshold certificates." },
  { n: 2, title: "Apparent cross-layer wins are single layers in disguise", evidence: "The only mechanism that detected anything, a pattern miner, equals one layer's zero-false-positive ceiling exactly." },
  { n: 3, title: "Valid fusion cannot beat the best layer without assuming independence", evidence: "An anytime-valid e-process detects a set identical to one layer's (Jaccard 1.0000). A learned alarm ranks attacks at AUROC 0.974 but cannot operate within a 2% false-alarm budget." },
  { n: 4, title: "Pipelines destroy evidence at their interfaces", evidence: "A four-check audit found 7 such points in DIDA. Llama Guard's safe or unsafe verdict turns an AUROC 0.714 ranking into a single bit (0.500)." },
  { n: 5, title: "It is not just our system", evidence: "On LLM Guard plus Llama Guard 3, the deployed rule catches 0 of 107 and dependence-robust fusion 0. Independence-assuming fusion catches 10, as predicted." },
  { n: 6, title: "More layers can mean more places to hide", evidence: "66.7 to 85.2% of DIDA's headroom is undefended against a distributed attacker (37.4% on the third-party stack)." },
] as const;
