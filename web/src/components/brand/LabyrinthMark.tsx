import { forwardRef } from "react";

/** The DIDA mark: five nested D walls, staggered openings, one protected core. Paths copied from assets/logo/dida-mark.svg. */
export const WALL_PATHS = [
  { d: "M20.00,100.00 V20.00 H100.00 A80.00,80.00 0 0 1 100.00,180.00 H20.00 Z", dash: "97.024 2.976", off: 77.512 },
  { d: "M36.00,100.00 V36.00 H100.00 A64.00,64.00 0 0 1 100.00,164.00 H36.00 Z", dash: "96.281 3.719", off: 48.14 },
  { d: "M52.00,100.00 V52.00 H100.00 A48.00,48.00 0 0 1 100.00,148.00 H52.00 Z", dash: "95.041 4.959", off: 18.52 },
  { d: "M68.00,100.00 V68.00 H100.00 A32.00,32.00 0 0 1 100.00,132.00 H68.00 Z", dash: "92.561 7.439", off: 3.281 },
  { d: "M84.00,100.00 V84.00 H100.00 A16.00,16.00 0 0 1 100.00,116.00 H84.00 Z", dash: "85.122 14.878", off: 54.061 },
];

export const LabyrinthMark = forwardRef<SVGSVGElement, { className?: string; title?: string; trace?: string; decorative?: boolean }>(
  function LabyrinthMark({ className, title = "DIDA", trace, decorative }, ref) {
    return (
      <svg ref={ref} viewBox="0 0 200 200" className={className} role={decorative ? undefined : "img"} aria-label={decorative ? undefined : title} aria-hidden={decorative ? true : undefined} fill="none">
        {!decorative && <title>{title}</title>}
        <g strokeWidth={9} strokeLinejoin="miter" strokeLinecap="butt" stroke="#EFEBE3">
          {WALL_PATHS.map((w, i) => (
            <path key={i} className={`wall wall-${i}`} d={w.d} pathLength={100} strokeDasharray={w.dash} strokeDashoffset={w.off} />
          ))}
        </g>
        {trace && <path className="trace" d={trace} stroke="#FF4F1F" strokeWidth={3.2} strokeLinejoin="round" strokeLinecap="round" opacity={0} />}
        <rect className="core" x={94} y={94} width={12} height={12} fill="#FF4F1F" />
      </svg>
    );
  },
);
