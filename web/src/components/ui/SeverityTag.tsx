import clsx from "clsx";

/** Severity is an orange intensity ramp plus a text label, so colour is never the only carrier. */
const RAMP: Record<string, { bg: string; fg: string }> = {
  CLEAN: { bg: "rgb(111 108 102 / .18)", fg: "var(--bone-3)" },
  LOW: { bg: "rgb(255 79 31 / .12)", fg: "var(--bone-2)" },
  MEDIUM: { bg: "rgb(255 79 31 / .24)", fg: "var(--bone)" },
  HIGH: { bg: "rgb(255 79 31 / .48)", fg: "var(--bone)" },
  CRITICAL: { bg: "var(--signal)", fg: "var(--ink-0)" },
};

export function SeverityTag({ severity, blocked, className }: { severity: string; blocked?: boolean; className?: string }) {
  const s = RAMP[severity] ?? RAMP.CLEAN;
  return (
    <span className={clsx("num inline-flex h-5 items-center gap-1 rounded-[var(--radius-chip)] px-1.5 text-[0.7rem] font-medium", className)} style={{ background: s.bg, color: s.fg }}>
      {(severity === "CRITICAL" || blocked) && <svg width="8" height="8" viewBox="0 0 8 8" aria-hidden><rect width="8" height="8" fill="currentColor" /></svg>}
      {severity}
    </span>
  );
}
