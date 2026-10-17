import Link from "next/link";
import { Wordmark } from "@/components/brand/Wordmark";
import { GITHUB_URL, RESULTS_URL, ROUTES } from "@/lib/constants/routes";

export function Footer() {
  const cls = "text-sm text-bone-2 transition-colors hover:text-bone";
  return (
    <footer className="relative border-t border-line" style={{ zIndex: 10 }}>
      <div className="container-x flex flex-col gap-10 py-14 md:flex-row md:items-start md:justify-between">
        <div className="max-w-sm">
          <Wordmark />
          <p className="mt-4 text-sm text-bone-2">Five security layers in front of your LLM app, and a measured look at whether stacking them works.</p>
        </div>
        <nav aria-label="Footer" className="flex flex-wrap gap-x-8 gap-y-3">
          <Link className={cls} href={ROUTES.research}>Research</Link>
          <Link className={cls} href={ROUTES.playground}>Playground</Link>
          <Link className={cls} href={ROUTES.console}>Console</Link>
          <a className={cls} href={GITHUB_URL} target="_blank" rel="noreferrer">GitHub</a>
          <a className={cls} href={RESULTS_URL} target="_blank" rel="noreferrer">results.md</a>
        </nav>
      </div>
      <div className="container-x pb-10 text-sm text-bone-3">Built by Gokul Iyer and collaborators.</div>
    </footer>
  );
}
