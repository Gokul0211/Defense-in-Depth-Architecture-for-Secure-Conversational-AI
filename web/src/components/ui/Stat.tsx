import type { ReactNode } from "react";
import { SourceNote } from "./SourceNote";

export function Stat({ value, label, source }: { value: ReactNode; label: string; source: string }) {
  return (
    <div>
      <div className="num text-4xl font-medium tracking-tight text-bone md:text-5xl">{value}<SourceNote source={source} /></div>
      <p className="mt-2 max-w-[28ch] text-sm text-bone-2">{label}</p>
    </div>
  );
}
