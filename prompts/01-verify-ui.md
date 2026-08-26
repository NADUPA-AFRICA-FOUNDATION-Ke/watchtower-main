# Task 01 — Render the UI and fix what's broken

Paste this as your first message in Claude Code, or run `claude` and say
"follow prompts/01-verify-ui.md".

---

## Prompt

Read `CLAUDE.md` first — it has the architecture, the design tokens, and the
decisions that shouldn't be reversed. Then do this.

**Context.** The web UI in `web/static/` was written but has never been rendered
in a browser. It was verified structurally only: every element the script
targets exists, every class it applies is styled, every SSE event it listens for
is one the server sends. That says nothing about whether it *looks* right or
whether the interactions work. Treat it as unverified code, not working code.

**Goal.** Get to a state where you have personally seen every screen and state
render correctly at desktop and mobile widths, and every bug you found is fixed
with a test or a note explaining why it isn't testable.

**Method.**

1. `bash setup.sh && source .venv/bin/activate && python run.py serve`
2. Open `http://127.0.0.1:8000` and look at it. If you have Playwright or any
   headless browser available, install it and take screenshots at 1440px,
   820px and 380px wide — a screenshot tells you more than reading the CSS. If
   you have no browser at all, say so plainly and ask me to screenshot it rather
   than guessing at layout from the source.
3. Work through the suspect list below.
4. Fix what's broken. After every change: `python smoke_test.py && python
   sweep_test.py && python web_test.py`. All three must stay green.

**Suspect list — check these specifically, they're the ones I couldn't verify.**

*Functional*

- **Does the sweep re-run itself after finishing?** `EventSource` auto-reconnects
  when the server closes the stream. The `done` handler calls `finish()` which
  closes it, but that's a race with the connection close. If a sweep silently
  fires twice, this is why. Verify with the server log — one sweep should
  produce one set of source hits, not two.
- Does SSE actually stream, or does everything arrive at once at the end?
  Watch the lanes fill. If they all populate simultaneously, something is
  buffering.
- Does a slow real sweep (60s+) hold the connection, or does it time out?
- The Archive tab returns nothing until a sweep is saved. The web UI has no
  save control — `/api/sweep` takes `save=true` but nothing in the frontend
  sends it. Either wire up a "Keep results" toggle or make the empty state say
  how to populate it.

*Layout*

- Mobile at 380px. The breakpoint is 820px. Check `.lane` (a 3-column grid),
  the `.field` stacking, and that the sidebar drops below the findings.
- Long titles and long URLs in `.card` — there's no `word-break` on them, so a
  200-character headline or an unbroken URL may blow out the card.
- `.side` is `position: sticky; top: 72px`. Verify it behaves against the
  52px sticky header and doesn't overlap or jitter.
- The `.lane.pending` scan animation is a `::after` translating inside an
  `overflow: hidden` bar. Confirm it actually sweeps rather than sitting still
  or escaping the bar.
- The `.gauge` segments and `--band` colour: the custom property is set inline
  on `.card` by JS and read by `.gauge i.on` and `.score`. Confirm the colours
  differ visibly between HIGH / MED / LOW / WEAK.
- Fonts load from Google Fonts over the network. Check the fallback looks
  acceptable offline, since this tool may run on a machine without open egress.

*States you have to force*

These never appear in normal use, so trigger them deliberately:

- Empty result — sweep for nonsense like `qxzptv nothing`.
- Server error — stop the server mid-sweep and watch what the page does.
- No sources selected — deselect every chip and submit.
- Bad archive syntax — search `AND OR` in the Archive tab.
- Keyboard only: tab through the whole page. Every control needs a visible
  focus ring. The chips and segmented buttons are custom, so they're the risk.
- `prefers-reduced-motion: reduce` — the scan animation should stop.

**Constraints.**

- No framework, no build step, no npm. Vanilla JS and CSS custom properties.
  This is deliberate: the whole point is `python run.py serve` and nothing else.
- Stay inside the existing palette and type scale in `CLAUDE.md`. If you think a
  token is wrong, say why and propose a change — don't quietly introduce a new
  colour.
- Don't add a generic spinner. The source lanes are the signature element and
  they exist so a silent zero-hit source is *visible*.
- Don't loosen `obey_robots`, remove the retention purge, or add
  Instagram/TikTok/LinkedIn/X. `CLAUDE.md` explains why.
- Don't change SSE event names or `Item` field names without updating
  `web_test.py` and `CLAUDE.md` in the same commit.

**Report back, in this order.**

1. What was actually broken, with the specific symptom you observed. Not "fixed
   responsive issues" — say what looked wrong and at what width.
2. What you changed and why.
3. What you could not verify and why.
4. Anything in the suspect list that turned out to be fine, so I know it was
   checked rather than skipped.

Be direct about failure. If the page is a mess, say so. If you couldn't render
it, say that instead of inferring layout correctness from reading the CSS —
that's the mistake that produced this task in the first place.
