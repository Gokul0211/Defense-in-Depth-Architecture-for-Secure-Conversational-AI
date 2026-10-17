import { LabyrinthMark } from "./LabyrinthMark";

export function Wordmark({ className = "" }: { className?: string }) {
  return (
    <span className={`inline-flex items-center gap-2.5 ${className}`}>
      <LabyrinthMark className="size-7" decorative />
      <span className="text-[1.05rem] font-semibold tracking-[0.04em]">DIDA</span>
    </span>
  );
}
