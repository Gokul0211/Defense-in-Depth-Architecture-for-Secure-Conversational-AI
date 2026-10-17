import { RESULTS_URL } from "@/lib/constants/routes";

/** Footnote marker for a number. Hover or focus shows where it came from. */
export function SourceNote({ source, href = RESULTS_URL }: { source: string; href?: string }) {
  return (
    <a href={href} target="_blank" rel="noreferrer" title={`Source: ${source}`} aria-label={`Source: ${source}`}
       className="group relative ml-1 inline-flex size-4 items-center justify-center align-super text-[0.65rem] text-bone-3 hover:text-signal">
      <span aria-hidden>*</span>
      <span role="tooltip" className="pointer-events-none absolute bottom-full left-1/2 z-20 mb-1 w-max max-w-56 -translate-x-1/2 rounded-[var(--radius-chip)] bg-ink-3 px-2 py-1 text-xs font-normal leading-snug text-bone opacity-0 transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100">
        {source}
      </span>
    </a>
  );
}
