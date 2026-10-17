import type { Metadata } from "next";
import { Playground } from "@/components/playground/Playground";
import { Footer } from "@/components/sections/Footer";

export const metadata: Metadata = { title: "Playground", description: "Run real requests through DIDA's endpoints." };

export default function PlaygroundPage() {
  return (
    <>
      <main id="main" tabIndex={-1} className="container-x pb-28 pt-36">
        <h1 className="display max-w-[14ch]">Playground</h1>
        <p className="measure mb-12 mt-6 text-lg text-bone-2">Every tool here calls a real endpoint on your running backend. Nothing is canned.</p>
        <Playground />
      </main>
      <Footer />
    </>
  );
}
