import clsx from "clsx";
import type { ReactNode } from "react";

/** Square chip (not a pill): the radius system reserves pills for controls. */
export function Badge({ children, tone = "neutral", className }: { children: ReactNode; tone?: "neutral" | "signal"; className?: string }) {
  return (
    <span className={clsx("inline-flex h-6 items-center rounded-[var(--radius-chip)] px-2 text-xs font-medium", tone === "signal" ? "bg-signal-dim text-signal" : "bg-ink-3 text-bone-2", className)}>
      {children}
    </span>
  );
}
