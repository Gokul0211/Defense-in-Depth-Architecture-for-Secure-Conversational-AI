import clsx from "clsx";
export function Skeleton({ className }: { className?: string }) {
  return <div aria-hidden className={clsx("animate-pulse rounded-[var(--radius-chip)] bg-ink-3", className)} />;
}
