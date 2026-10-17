import { Hero } from "@/components/sections/Hero";
import { Problem } from "@/components/sections/Problem";
import { Journey } from "@/components/sections/Journey";
import { SplitAttack } from "@/components/sections/SplitAttack";
import { AttackStory } from "@/components/sections/AttackStory";
import { ProbeShowcase } from "@/components/sections/ProbeShowcase";
import { KitBento } from "@/components/sections/KitBento";
import { LiveMetrics } from "@/components/sections/LiveMetrics";
import { Process } from "@/components/sections/Process";
import { CtaBand } from "@/components/sections/CtaBand";
import { Footer } from "@/components/sections/Footer";

export default function Home() {
  return (
    <>
      <main id="main" tabIndex={-1}>
        <Hero />
        <Problem />
        <Journey />
        <SplitAttack />
        <AttackStory />
        <ProbeShowcase />
        <KitBento />
        <LiveMetrics />
        <Process />
        <CtaBand />
      </main>
      <Footer />
    </>
  );
}
