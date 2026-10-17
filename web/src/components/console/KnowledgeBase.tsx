"use client";
import { useEffect, useRef, useState } from "react";
import clsx from "clsx";
import { useApiHealth } from "@/hooks/useApiHealth";
import { KB_PRESETS } from "@/lib/content/samples";
import { useChat } from "@/lib/state/chat-store";
import type { KbChunk } from "@/lib/api/types";

function statusOf(c: KbChunk): { label: string; hot: boolean } {
  if (c.quarantined) return { label: "QUARANTINED", hot: true };
  if (c.review_flagged) return { label: "REVIEW", hot: true };
  return { label: "ADMITTED", hot: false };
}

/**
 * The documents the chat retrieves from. Every document is scored by L2 when it is added, and again when
 * it is retrieved; only admitted chunks that match a question are put in the model's prompt.
 */
export function KnowledgeBase({ onAsk }: { onAsk: (question: string) => void }) {
  const { kb, kbBusy, kbNote, refreshKb, addDoc, addPdf, tamper } = useChat();
  const health = useApiHealth();
  const online = health.status === "online";
  const [text, setText] = useState("");
  const [asks, setAsks] = useState<string[]>([]);
  const file = useRef<HTMLInputElement>(null);

  useEffect(() => { if (online) void refreshKb(); }, [online, refreshKb]);

  const add = async (body: string, source: string, ask?: string) => {
    await addDoc(body, source);
    if (ask) setAsks((a) => (a.includes(ask) ? a : [...a, ask]));
  };

  return (
    <div data-lenis-prevent className="pane-scroll min-h-0 flex-1 space-y-5 overflow-y-auto p-4">
      <div>
        <p className="text-sm font-medium">Knowledge base</p>
        <p className="mt-1 text-xs text-bone-2">Add a document, then ask a question that matches it. The real backend scores the document with L2 and the chat answers from whatever it admits.</p>
      </div>

      <div className="flex flex-col items-start gap-2" role="group" aria-label="Sample documents">
        {KB_PRESETS.map((p) => (
          <button key={p.id} disabled={!online || kbBusy} onClick={() => add(p.text, p.source, p.ask)} title={p.hint}
            className="rounded-full border border-line px-3.5 py-2 text-left text-xs text-bone-2 transition-colors hover:border-line-strong hover:bg-ink-2 hover:text-bone disabled:opacity-40">
            <span className="text-bone">{p.label}</span> <span className="text-bone-3">{p.hint}</span>
          </button>
        ))}
      </div>

      <div>
        <label htmlFor="kb-text" className="text-xs text-bone-2">Or paste your own (over 600 characters is judged as a document)</label>
        <textarea id="kb-text" rows={4} value={text} onChange={(e) => setText(e.target.value)} disabled={!online}
          className="num mt-1.5 w-full resize-y rounded-[var(--radius-input)] border border-line bg-ink-2 p-2.5 text-xs text-bone placeholder:text-bone-3" placeholder="Document text" />
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <button disabled={!online || kbBusy || !text.trim()} onClick={async () => { await add(text, "pasted_document"); setText(""); }}
            className="h-8 rounded-full bg-signal px-4 text-xs font-medium text-ink-0 hover:bg-[#ff6a40] disabled:opacity-40">{kbBusy ? "Scoring" : "Add document"}</button>
          <input ref={file} type="file" accept="application/pdf,.pdf" className="sr-only-text" aria-label="Upload a PDF"
            onChange={async (e) => { const f = e.target.files?.[0]; if (f) await addPdf(f); if (file.current) file.current.value = ""; }} />
          <button disabled={!online || kbBusy} onClick={() => file.current?.click()}
            className="h-8 rounded-full border border-line-strong px-4 text-xs text-bone hover:bg-ink-3 disabled:opacity-40">Upload PDF</button>
        </div>
      </div>

      {kbNote && (
        <p role="status" className={clsx("rounded-[var(--radius-input)] border px-3 py-2 text-xs", kbNote.tone === "ok" ? "border-line text-bone-2" : "border-signal/60 bg-signal-dim text-bone")}>{kbNote.text}</p>
      )}

      {asks.length > 0 && (
        <div>
          <p className="text-xs text-bone-3">Ask something that retrieves it</p>
          <div className="mt-2 flex flex-col items-start gap-2">
            {asks.map((a) => <button key={a} onClick={() => onAsk(a)} className="rounded-full border border-line px-3.5 py-2 text-left text-xs text-bone-2 hover:border-line-strong hover:bg-ink-2 hover:text-bone">{a}</button>)}
          </div>
        </div>
      )}

      <div>
        <p className="text-xs text-bone-3">{kb.length === 0 ? "No documents yet." : `${kb.length} document${kb.length === 1 ? "" : "s"} on the backend, shared by every chat`}</p>
        <ul className="mt-2 space-y-2">
          {kb.map((c) => {
            const st = statusOf(c);
            const threat = c.metadata.document_threat?.available === false ? null : c.metadata.document_threat?.threat;
            return (
              <li key={c.chunk_id} className="surface-2 p-3 text-xs">
                <div className="num flex flex-wrap items-center gap-2">
                  <span className={clsx("inline-flex h-5 items-center rounded-[var(--radius-chip)] px-1.5 text-[0.68rem] font-medium", st.hot ? "bg-signal text-ink-0" : "bg-ink-3 text-bone-2")}>{st.label}</span>
                  <span className="min-w-0 flex-1 truncate text-bone">{c.metadata.source ?? "unknown source"}</span>
                  <span className="text-bone-3">{c.chunk_id}</span>
                </div>
                <p className="mt-1.5 line-clamp-2 text-bone-2">{c.text}</p>
                <div className="num mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[0.65rem] text-bone-3">
                  {typeof c.metadata.trust_score === "number" && <span>trust {c.metadata.trust_score.toFixed(2)}</span>}
                  {typeof threat === "number" && <span>threat {threat.toFixed(2)}</span>}
                  {c.reason && <span className="min-w-0 truncate" title={c.reason}>{c.reason}</span>}
                  {st.label === "ADMITTED" && (
                    <button disabled={kbBusy} onClick={() => tamper(c.chunk_id)} title="Edit the stored text without re-signing it, to show the integrity check"
                      className="ml-auto text-bone-2 underline-offset-4 hover:text-signal hover:underline disabled:opacity-40">Tamper with it</button>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}
