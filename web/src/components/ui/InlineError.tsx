import { WarningCircle } from "@phosphor-icons/react/dist/ssr";
import type { ReactNode } from "react";

export function InlineError({ title, children, id }: { title: string; children?: ReactNode; id?: string }) {
  return (
    <div id={id} role="alert" className="flex gap-3 rounded-[var(--radius-input)] border border-signal/40 bg-signal-dim p-3 text-sm">
      <WarningCircle size={18} className="mt-0.5 shrink-0 text-signal" aria-hidden />
      <div><p className="font-medium text-bone">{title}</p>{children && <p className="mt-0.5 text-bone-2">{children}</p>}</div>
    </div>
  );
}
