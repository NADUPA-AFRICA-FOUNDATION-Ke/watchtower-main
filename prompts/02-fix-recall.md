# Task 02 — Fix zero recall, then accuracy

Run `claude` and say "follow prompts/02-fix-recall.md".

---

## Prompt

Read `CLAUDE.md` first.

**The situation.** A live sweep returned 0 hits from all six backends with no
exceptions raised. That is not a tuning problem — there is nothing to tune. Fix
recall first. Do not touch scoring, ranking or diversity until real results are
coming back.

**Start here.** `python diagnose.py` hits each backend's real endpoint and
reports the actual failure reason, which the sweep currently swallows. Run it
before changing anything and paste the table into your first reply.

---

### Bug 1 — robots.txt is being applied to API calls

**Root cause, confirmed.** `en.wikipedia.org/robots.txt` contains
`Disallow: /w/` and `Disallow: /api/`. The `wikipedia()` backend calls
`en.wikipedia.org/w/api.php`, so `Fetcher.allowed()` refuses it,
`get()` returns `ok=False`, and the backend returns `[]` without raising.
`news.google.com` and `mastodon.social` are likely the same — `diagnose.py`
will confirm which.

This is a category error on my part. robots.txt governs crawlers indexing
pages. It is not the access-control mechanism for a documented public JSON API
you are calling as an intended consumer. Wikipedia publishes that API for this
purpose and governs it with its own rate-limit policy and user-agent rules.

**Fix.** Separate the two activities:

- **API calls** to declared endpoints in `core/sources.py` — skip the robots
  check. Add an `api=True` argument to `Fetcher.get()`, or a separate method.
- **Crawling** arbitrary article bodies in `sweep.py` and `adapters/` — keep
  robots on. That's genuine crawling of pages, and `obey_robots` must keep
  governing it.

Do not solve this by setting `obey_robots: false` globally. That reverses a
deliberate decision documented in `CLAUDE.md` and removes the protection where
it actually belongs.

While you're in there: Wikipedia and SEC EDGAR both want a descriptive user
agent with contact details. Check `config.yaml` still has the placeholder
`you@example.com` and flag it if so — a 403 from EDGAR is usually this.

### Bug 2 — silent zeros, which is the real accuracy bug

Every backend returns `[]` on failure. `sweep.py` records `per_source[name] = 0`
and moves on. So the UI renders "0 hits" identically for *blocked*, *404*,
*timed out*, and *genuinely nothing found*.

For screening work that distinction is the whole point. "No adverse media
exists" and "we could not look" must never render the same way. A clean result
that is actually a failed fetch is a false negative someone signs off on.

**Fix.** Backends raise a `SourceError` on fetch failure instead of returning
`[]`. `sweep.py` already catches per-backend exceptions into `result.errors`
and the frontend already renders a failed lane — wire the real reason through
to both. An empty sweep where any source errored must say so prominently, not
render as "Nothing came back".

### Bug 3 — sequential fan-out

`core/sweep.py` fans out with a plain `for` loop; `workers` only covers body
fetching. One slow source stalls every lane behind it, which is why the live
run appeared frozen then completed all at once, and why gdelt alone took 58s.

Parallelise the fan-out with `ThreadPoolExecutor`. Per-domain rate limiting
still holds — each backend is a different host and `Fetcher._throttle` is
already lock-guarded. Verify that claim rather than trusting it.

### Bug 4 — opensanctions ships enabled but dead

It's in `DEFAULT_BACKENDS` *and* `needs_key`, so `app.js`'s
`needs_key && !default` guard never fires. It ships selected and silently
returns zero. Have `/api/sources` report an `available` flag based on whether
the key is actually set, and disable on that rather than on `default`.

---

## Only after real results are flowing

Re-run a live sweep, confirm non-zero hits, then improve accuracy in this order:

1. **Count corroboration instead of discarding it.** `Item.content_hash` dedupe
   collapses a story syndicated across five outlets into one row and throws the
   rest away. The number of independent domains carrying a story is the cheapest
   strong signal that it's real. Keep the count and the domain list; surface
   "corroborated by N sources" on the card. Do this before anything else.
2. **Ground summaries with the Citations API** so each summary carries the
   verbatim source sentences supporting it. Docs:
   <https://platform.claude.com/docs/en/build-with-claude/citations>. If Claude
   can't produce a supporting span, the claim shouldn't survive.
3. **Mark headline-only items.** GDELT with `fetch_body=False` returns headlines;
   they're currently summarised as though they were full articles. Label them
   and cap their score.
4. **Tier the sources.** A regulator circular and a content farm currently carry
   identical weight. Primary sources should outrank aggregators.
5. **Entity disambiguation via GLEIF** (`api.gleif.org`, free, no registration)
   to attach legal entity identifiers to company matches. Name collision is the
   classic adverse-media false positive.

## Constraints

- All three suites stay green after every change.
- Don't disable robots globally, don't remove the retention purge, don't add
  the platforms `CLAUDE.md` excludes.
- Update `CLAUDE.md` in the same commit when you change something structural.
  Remove the hardcoded check counts while you're there — they already drifted
  (said 33, actual 36). Let the suites report their own totals.

## Report back

What `diagnose.py` said before and after, which sources now return real data,
and anything that's still returning zero with the reason. Be specific about
what you could not verify.
