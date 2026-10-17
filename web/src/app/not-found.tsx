import { ButtonLink } from "@/components/ui/Button";
import { LabyrinthMark } from "@/components/brand/LabyrinthMark";
import { Footer } from "@/components/sections/Footer";

export default function NotFound() {
  return (
    <>
      <main id="main" tabIndex={-1} className="container-x grid min-h-[80dvh] place-items-center py-32 text-center">
        <div>
          <LabyrinthMark decorative className="mx-auto size-32 opacity-80" />
          <h1 className="h2 mt-8">No path leads here</h1>
          <p className="mx-auto mt-4 max-w-[40ch] text-bone-2">That page does not exist. The layers are on the home page.</p>
          <div className="mt-8"><ButtonLink href="/" variant="secondary">Back to home</ButtonLink></div>
        </div>
      </main>
      <Footer />
    </>
  );
}
