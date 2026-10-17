import type { Metadata } from "next";
import { Footer } from "@/components/sections/Footer";
import { ScrollReveal } from "@/components/animation/ScrollReveal";
import { SourceNote } from "@/components/ui/SourceNote";
import { Chapters } from "@/components/research/Chapters";
import { CONTRIBUTIONS, KIT_ORDER, MECHANISM_ORDER } from "@/lib/content/contributions";
import { ENGINEERING, GUARDS } from "@/lib/content/facts";
import { GITHUB_URL } from "@/lib/constants/routes";

export const metadata: Metadata = { title: "Research", description: "Do layered defenses compose? Six findings, eight contributions and the numbers behind them." };

const code = (p: string) => `${GITHUB_URL}/blob/main/${p}`;

function Contribution({ id }: { id: keyof typeof CONTRIBUTIONS }) {
  const c = CONTRIBUTIONS[id];
  return (
    <ScrollReveal as="article" className="grid gap-3 border-t border-line py-8 md:grid-cols-[4rem_1fr_1fr]">
      <p className="num text-signal">{c.id}</p>
      <div><h3 className="text-xl font-semibold tracking-tight">{c.name}</h3><p className="mt-2 max-w-[52ch] text-bone-2">{c.truth}</p></div>
      <div><p className="text-bone">{c.weight}</p><a className="num mt-3 inline-block text-sm text-bone-3 underline-offset-4 hover:text-signal hover:underline" href={code(c.code)} target="_blank" rel="noreferrer">{c.code}</a></div>
    </ScrollReveal>
  );
}

export default function ResearchPage() {
  return (
    <>
      <main id="main" tabIndex={-1} className="container-x pb-28 pt-36">
        <ScrollReveal>
          <h1 className="display max-w-[16ch]">Do layered defenses compose?</h1>
          <p className="mt-6 max-w-[44ch] text-xl text-bone-2">Not the way the industry assumes. Six findings, each with something you can move.</p>
        </ScrollReveal>

        <Chapters />

        <div className="mt-12 rounded-[var(--radius-panel)] bg-ink-0/85 px-4 py-2 backdrop-blur-sm md:px-8">
        <section aria-labelledby="kit" className="mt-28">
          <h2 id="kit" className="h2">The kit</h2>
          <p className="measure mt-4 text-bone-2">The theory and the measurement tools. This is the most original part of the work.</p>
          <div className="mt-8">{KIT_ORDER.map((id) => <Contribution key={id} id={id} />)}</div>
        </section>

        <section aria-labelledby="mech" className="mt-28">
          <h2 id="mech" className="h2">Four mechanisms, and where each stops</h2>
          <p className="measure mt-4 text-bone-2">The cross-layer tricks people usually reach for, with the limit the kit exposes for each.</p>
          <div className="mt-8">{MECHANISM_ORDER.map((id) => <Contribution key={id} id={id} />)}</div>
        </section>

        <section aria-labelledby="eng" className="mt-28">
          <h2 id="eng" className="h2">What the engineering bought</h2>
          <p className="measure mt-4 text-bone-2">Each row is a measured root cause and a repair, not a threshold tweak.</p>
          <div className="mt-8 overflow-x-auto">
            <table className="w-full min-w-[40rem] text-left text-sm">
              <caption className="sr-only-text">Before and after for each repaired problem</caption>
              <thead className="text-bone-3"><tr><th scope="col" className="py-3 pr-4 font-normal">Problem found</th><th scope="col" className="py-3 pr-4 font-normal">Before</th><th scope="col" className="py-3 font-normal">After</th></tr></thead>
              <tbody>{ENGINEERING.map((r) => (
                <tr key={r.problem} className="border-t border-line"><th scope="row" className="max-w-sm py-3 pr-4 font-normal text-bone-2">{r.problem}</th><td className="num py-3 pr-4 text-bone-3">{r.before}</td><td className="num py-3 text-bone">{r.after}</td></tr>
              ))}</tbody>
            </table>
          </div>
        </section>

        <section aria-labelledby="guards" className="mt-28">
          <h2 id="guards" className="h2">Against third-party guards</h2>
          <div className="mt-8 overflow-x-auto">
            <table className="w-full min-w-[40rem] text-left text-sm">
              <caption className="sr-only-text">DIDA compared with Llama Guard 3 and ProtectAI DeBERTa v2</caption>
              <thead className="text-bone-3"><tr><th scope="col" className="py-3 pr-4 font-normal">Measure</th>{GUARDS.columns.map((c) => <th key={c} scope="col" className="py-3 pr-4 font-normal">{c}</th>)}</tr></thead>
              <tbody>{GUARDS.rows.map((r) => (
                <tr key={r.metric} className="border-t border-line"><th scope="row" className="py-3 pr-4 font-normal text-bone-2">{r.metric}</th>
                  {r.values.map((v, i) => <td key={i} className={`num py-3 pr-4 ${i === r.best ? "text-signal" : "text-bone-2"}`}>{v}</td>)}</tr>
              ))}</tbody>
            </table>
          </div>
          <p className="measure mt-6 text-sm text-bone-2">ProtectAI wins TensorTrust at its default threshold, but it flags 43% of benign trigger-word prompts. Held to DIDA's false-positive rate, its recall falls to 0.779. The best value in each row is marked in orange.<SourceNote source="README, Against third-party guards" /></p>
        </section>
        </div>
      </main>
      <Footer />
    </>
  );
}
