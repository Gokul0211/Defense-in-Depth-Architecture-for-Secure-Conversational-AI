import type { ReactNode } from "react";

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex h-full min-h-40 flex-col items-center justify-center gap-1 p-6 text-center">
      <p className="text-sm font-medium text-bone">{title}</p>
      {children && <p className="max-w-[34ch] text-sm text-bone-2">{children}</p>}
    </div>
  );
}
