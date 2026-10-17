"use client";
import Link from "next/link";
import { EmptyState } from "@/components/ui/EmptyState";
import { SeverityTag } from "@/components/ui/SeverityTag";
import { useConsole } from "@/lib/state/console-store";
import clsx from "clsx";

export function SessionList() {
  const sessions = useConsole((s) => s.sessions);
  const sel = useConsole((s) => s.selectedSessionId);
  const select = useConsole((s) => s.selectSession);
  const list = Object.values(sessions).sort((a, b) => (b.last_event_ts ?? 0) - (a.last_event_ts ?? 0));
  if (!list.length) return <EmptyState title="No sessions yet">Sessions appear as soon as a layer reports an event.</EmptyState>;
  return (
    <table className="w-full text-left text-xs">
      <caption className="sr-only-text">Sessions</caption>
      <thead className="sticky top-0 bg-ink-1 text-bone-3"><tr><th scope="col" className="px-3 py-2 font-normal">Session</th><th scope="col" className="py-2 font-normal">Risk</th><th scope="col" className="py-2 text-right font-normal">Overall</th><th scope="col" className="py-2 text-right font-normal">Turns</th><th scope="col" className="px-3 py-2 text-right font-normal">State</th></tr></thead>
      <tbody>{list.map((s) => (
        <tr key={s.session_id} className={clsx("border-t border-line hover:bg-ink-2", sel === s.session_id && "bg-ink-3")}>
          <td className="num px-3 py-2"><button onClick={() => select(s.session_id)} className="max-w-[9rem] truncate text-left text-bone">{s.session_id}</button></td>
          <td className="py-2"><SeverityTag severity={s.risk} /></td>
          <td className="num py-2 text-right">{s.overall.toFixed(2)}</td>
          <td className="num py-2 text-right text-bone-2">{s.turn_count}</td>
          <td className="px-3 py-2 text-right">{s.terminated ? <Link href={`/console/sessions/${encodeURIComponent(s.session_id)}`} className="text-signal underline-offset-4 hover:underline">Terminated</Link> : <Link href={`/console/sessions/${encodeURIComponent(s.session_id)}`} className="text-bone-2 underline-offset-4 hover:underline">Open</Link>}</td>
        </tr>
      ))}</tbody>
    </table>
  );
}
