# DIDA web

Next.js (App Router) frontend for DIDA. Replaces `dashboard/static/`. Built from `FRONTEND_SPEC.md`.

```bash
cp .env.example .env.local     # NEXT_PUBLIC_DIDA_API_URL=http://localhost:8080
npm install
npm run dev                    # http://localhost:3000
npm run build && npm run start
```

Backend: `python main.py` (from the repo root). The API must allow the frontend origin in `DIDA_CORS_ORIGINS`; the default is `http://localhost:3000,http://127.0.0.1:3000`, so run the UI on port 3000 or extend that list. The backend loads its models in the background after start; the first scans can take a few seconds longer until it finishes (`DIDA_WARMUP=0` disables this).

On a machine with little free RAM, `npm run build && npm run start` is steadier than `npm run dev` (Turbopack crashed with out-of-memory next to the backend on an 8 GB laptop).

## Deviations from FRONTEND_SPEC.md (update the spec to match)

| Spec | Built | Why |
|---|---|---|
| Anime.js v4 only, no GSAP | GSAP + ScrollTrigger | The brief now lists gsap.com. Call sites go through `src/lib/animations/` and `src/hooks/useGsap.ts`, so swapping back touches a few files. |
| shadcn/ui + Radix primitives | Hand-built Tabs, native `<dialog>`, menu | Fewer dependencies; keyboard behaviour covered. |
| Bento: C and D at 3x1 | C and D span 6 columns each | Eight cells cannot tile 12 columns as specified without a gap. |
| One Stage shared by hero and sticky section | One per section, each pauses offscreen | Simpler lifecycle. |
| AnimatedBorder, InteractiveBentoCard, Kbd | Not built | No section needs them. |
| Landing: WalkTheLayers 3D section | Journey (SVG map, scroll-driven). 3D now only in the hero. | Exact path control; one fewer WebGL context. |
| Console live labyrinth | Canvas 2D radar | Replayable as a pure function of events and a clock. |
| Backend touchpoints B4, B5 | Already in the repo; the UI uses `/sentinel/config/thresholds`, `/sentinel/demo`, `/sentinel/l1/scan` | |

## Verified against the real backend (2026-10-17)

Playground (all seven tools), landing probe, console stream, scenarios, reset and the session recorder were run against `python main.py`. Contract fixes made then: chat sends `content`; the demo list reads `desc`; L2 scores come from `metadata.document_threat.threat`; L4 shows WARNED at the live L4 warn threshold and sends the user's turn as history; L5 uses the live warn/block thresholds; image scans read `l1_score`/`chi_score`; L2 sample documents are over 600 characters because shorter text goes to a short-document bin that only alarms at 0.9997.

## Not verified

- Lighthouse and axe runs (spec section 19).
- Touch devices, and mobile layouts beyond CSS review.
- Reduced-motion mode was implemented but not tested in a browser.

See `UPDATE_STATUS.md` for what was implemented from the update plan.

## Optional

- `/?gpu=1` enables the experimental WebGPU particle storm (needs a WebGPU browser). Untested.
- New dependency: `lenis`.
