"use client";
import { useState } from "react";
import { Check, Copy } from "@phosphor-icons/react";

export function CodeBlock({ code, label }: { code: string; label?: string }) {
  const [done, setDone] = useState(false);
  const copy = async () => {
    try { await navigator.clipboard.writeText(code); setDone(true); setTimeout(() => setDone(false), 1600); } catch { /* clipboard unavailable */ }
  };
  return (
    <div className="surface-2 relative overflow-hidden">
      {label && <div className="flex items-center gap-2 border-b border-line px-4 py-2.5 text-xs text-bone-3"><span aria-hidden className="size-2 bg-ink-3" /><span aria-hidden className="size-2 bg-ink-3" /><span aria-hidden className="size-2 bg-signal" /><span className="ml-2">{label}</span></div>}
      <pre data-lenis-prevent-wheel className="num overflow-x-auto p-4 pr-14 text-[0.82rem] leading-relaxed text-bone"><code>{code}</code></pre>
      <button onClick={copy} aria-label={done ? "Copied" : "Copy code"} className="absolute right-2 top-2 grid size-9 place-items-center rounded-full text-bone-2 hover:bg-ink-3 hover:text-bone" style={{ top: label ? 46 : 8 }}>
        {done ? <Check size={16} className="text-signal" /> : <Copy size={16} />}
      </button>
      <span className="sr-only-text" role="status">{done ? "Copied to clipboard" : ""}</span>
    </div>
  );
}
