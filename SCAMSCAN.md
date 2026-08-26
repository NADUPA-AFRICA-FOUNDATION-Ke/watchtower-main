# scamscan

> One of two tools in this repo. See [README.md](README.md) for **watchtower**,
> the multi-source keyword sweep. They share nothing but the repo.

Keyword-driven scam discovery using Claude's server-side web search.

Runs from the CLI, or from the **scamscan side of the web UI** — `python run.py
serve` opens a page with watchtower's Sweep and Archive tabs on one side and
scamscan's Queue and Score tabs on the other. Same engine behind both; the web
layer calls `hunt()`, `score_finding()` and the store directly.

Claude proposes candidates; local Python code scores them. Anything that drives
analyst workload is computed in auditable code, not inside a prompt.

## Setup

```bash
pip install -r requirements.txt
# Either provider. Gemini is picked first when both keys are set — it has a
# free tier. Force one with SCAMSCAN_PROVIDER or search.provider in config.json.
export GEMINI_API_KEY=...                # aistudio.google.com/api-keys (free)
export ANTHROPIC_API_KEY=sk-ant-...      # platform.claude.com -> API keys

python scamscan.py models                # what your key can actually reach
python scamscan.py selftest              # free: config, schemas, lexicon
python scamscan.py hunt --config config.json --topics 1   # start with one topic
```

## Testing before you pay

Verified on a live free-tier Gemini key: **Google Search grounding is not
available on the Gemini free tier** for 3.x models, and the 2.5 models that had
500 free grounded requests/day now 404 for new keys. So `hunt` needs billing —
but three of the four things worth testing do not.

| What you want to check | Free? | How |
|---|---|---|
| Scoring quality — the thing that sets analyst workload | yes, entirely local | `scamscan.py test "<copy>" --url <url>`, or the **Score** tab |
| Lexicon, counter terms, thresholds | yes | same; every hit shows its source |
| Config, provider, schemas, model IDs | yes | `scamscan.py selftest`, `scamscan.py models` |
| The queries the model will actually run | yes — expansion uses no search tool | `scamscan.py hunt --topics 1 --dry-run` |
| Extraction from live pages | **no** | needs grounding |

Do the first four first. Scoring is where the quality lives, it is deterministic,
and it costs nothing to iterate on — a hunt only decides *which pages* reach it.

When you do move to paid, note that Gemini's **paid** tier includes 5,000 free
grounded searches per month across 3.x models before per-request billing starts,
and `--topics 1` is about 12 searches. Adding billing is not the same as
spending; it is what unlocks the allowance.

A dry run never writes to the database and reports `complete: false`, so it can
never be mistaken for a hunt that searched and found nothing.

**The provider changes the failure shape, not the pipeline.** Anthropic reports
a failed search as an error object inside a 200; Gemini answers anyway from the
model's own memory and the only evidence is negative — no grounding metadata.
The second is more dangerous, because the text comes back looking perfectly well
formed. `grounding_failures()` treats an ungrounded answer to a search query as
a query that never ran, and raises `HuntError` exactly like the Anthropic path.

Gemini free-tier keys are rate limited per minute; a daily quota exhaustion
stops the run and says so, a per-minute limit is retried with backoff.

## Commands

| Command | What it does |
|---|---|
| `hunt` | Expand seed topics into queries, search, extract, score, store |
| `hunt --dry-run` | Expand into queries and stop. No search, no cost, no writes — works on a Gemini free key |
| `models` | List the models this API key can actually reach |
| `queue` | Print the review queue, highest score first |
| `export --out queue.csv` | Dump everything to CSV |
| `dispose <fingerprint> confirmed\|false_positive\|unclear\|escalated` | Record an analyst verdict |
| `test "<text>" --url <url>` | Score sample text offline, no API calls |
| `selftest` | Lint the schemas, show which search tool the model gets, audit lexicon provenance |
| `selftest --live` | Prove structured outputs composes with server-side search (~1 search) |

In the browser, the **Queue** tab runs a hunt (stating the cost first), lists
the review queue with the full score breakdown, and records analyst verdicts.
The **Score** tab is `test` in a page — free, no API call, and it shows every
lexicon hit with the source it came from.

Two things the UI is careful about, for the same reason the CLI is: an empty
queue says plainly that it is a fact about the database and not about the
brand, and a query that could not be searched arrives on its own SSE event
(`unsearched`) and renders in the failure colour, never as a zero.

Use `test` heavily before your first real run. It costs nothing and it is how you
tune weights against examples you already know the answer to. Run `selftest`
after any config edit — it catches a schema or model mistake before you pay for
a search that then 400s.

## How scoring works

Four independent families, each 0-100, averaged with configurable weights:

- **lexicon** — weighted term hits across English, Kiswahili and Sheng, minus
  counter terms
- **artifact** — extracted phone numbers, paybills, tills, WhatsApp/Telegram
  links, crypto addresses, shortlinks, and explicit PIN/OTP requests
- **impersonation** — host similarity to official domains after NFKD
  normalisation and homoglyph folding, plus brand tokens and credential-themed
  hostnames. Official domains are hard-zeroed
- **model** — Claude's own confidence, as one vote among four rather than the
  verdict

Change `scoring.weights` in `config.json` to shift the balance. Drop `model` to
0 if you want a fully deterministic pass.

### The lexicon

Every term carries `[weight, "SOURCE"]`, and the source travels with the hit
into the score breakdown. A term you cannot trace to a published case is a term
you cannot defend when an analyst asks why a page was escalated, so `selftest`
reports how many terms are unsourced or `UNVERIFIED`.

| Source | What it is |
|---|---|
| `COMPASS2025` | Doğan, Gilbert & Kotut, *Easy Come, Easy Go: Phone Enabled Small-Scale Financial Grift*, ACM COMPASS '25 ([doi:10.1145/3715335.3736315](https://doi.org/10.1145/3715335.3736315)) — 73 Kenyan M-PESA users, 89 scams, with verbatim message samples |
| `SAFARICOM` | Safaricom fraud-awareness advisories and the 2026 M-PESA prompt alert |
| `CMA_CBK` | Capital Markets Authority / Central Bank of Kenya investor alerts |
| `DCI` | Directorate of Criminal Investigations recruitment- and investment-fraud warnings |
| `PRESS` | Kenyan press and Africa Check fact-checks reproducing scam SMS verbatim |
| `UNVERIFIED` | plausible, not traced to a published case. Low weights — replace from your own confirmed reports first |

Two things changed with the terms, and both are load-bearing:

**Matching is on word boundaries.** `term in text` was fine for invented terms
because they were long and distinctive. Real ones are not — `otp` fires inside
"adoption", `reversal` inside "irreversible", `act now` inside "contact
nowhere". A real lexicon on a substring matcher is a scoring family made mostly
of noise.

**Counter terms subtract.** The bait and the warning about the bait use the same
words: Safaricom's own advisory says "never share your PIN" and quotes the SMS
verbatim, and so does every news explainer. Without a subtraction the best page
written about a scam scores like the scam. Edit `counter_terms` in
`config.json`; they apply before the 0-100 clamp and the score never goes
negative.

The Sheng bucket is deliberately thin. Published fraud reporting quotes English
and Kiswahili, so the bare money nouns that used to sit here (`doo`, `chapaa`,
`mullah`) were removed — they mean "money" and carry no fraud signal. What
remains carries intent (`doublisha`) and is marked `UNVERIFIED`. This is the
bucket to build from your own case files.

## Structured outputs and the search tool

`hunt` sends `output_config.format` with a JSON schema, so the response shape is
enforced by the API rather than regex-scraped out of model prose. Two
consequences worth knowing:

- **`model_confidence` is `required` in the schema**, which removes the omission
  that used to cost a finding 25 points. The renormalisation in `score_finding`
  stays anyway — the offline `test` command and the text fallback below can
  still omit it, and a guarantee at one layer is not a reason to delete the
  defence at another.
- **A parse failure now raises.** Under a schema the API guarantees valid JSON
  matching it, so a failed parse is a broken contract, not prose to salvage.
  Salvaging it would produce `[]`, which reads as "searched, found nothing".

The API docs do not state whether `output_config.format` composes with a
server-side tool. Rather than assume, the run finds out: a 400 that names
`output_config`, `json_schema` or `output format` downgrades to text parsing for
the rest of the run, prints the reason, and repeats it in the closing summary.
Any other 400 — a credit-balance error, a bad model — propagates untouched.
`selftest --live` answers the question directly in two calls, one structured
without tools and one with web search.

The web search tool version follows the model. `web_search_20260209` adds
dynamic filtering, where Claude filters results in a code sandbox before they
reach the context window — better accuracy, fewer tokens — and exists only on
Opus 5/4.8/4.7/4.6, Sonnet 5, Sonnet 4.6 and Fable 5. On anything else the run
uses `web_search_20250305` and says so, rather than 400ing on every query.
`search.web_search_tool_version` pins it if you need to.

## Cost

Web search is billed separately from tokens, at roughly $10 per 1,000 searches.
With `queries_per_topic: 3` and `max_uses_per_query: 4`, one topic costs up to 12
searches. Six topics is up to 72 searches per run, so roughly $0.72 plus tokens.
A daily run across six topics lands near $25/month. Start with `--topics 1`.

## Dedupe

Fingerprint is the registrable domain plus a hash of the first 25 words of the
summary. Same site with the same copy collapses and increments `times_seen`.
Different site with the same copy stays separate on purpose — cross-site
duplication is the coordination signal you want to see, not noise to suppress.

## Prompt injection

Pages returned by search are untrusted data. The hunt prompt says so explicitly,
and scoring never executes anything from page content. If a page contains text
addressed to the model, that gets reported as evidence rather than followed.
Keep this property if you extend the tool: never let extracted content reach a
shell, a SQL string, or a follow-up prompt as an instruction.

## Known limits

- Only reaches the indexed web. Closed Facebook groups, Telegram channels,
  WhatsApp and most video content are invisible here. Those need separate pipes.
- Search index freshness lags. Certificate Transparency monitoring catches
  lookalike domains days earlier and costs nothing.
- Kenyan phone patterns are hardcoded in `ARTIFACT_PATTERNS`. Add Tanzania
  (+255) and Lesotho (+266) before running those markets.
- The lexicon is built from Kenyan sources, so it is a Kenya lexicon. Tanzania
  and Lesotho need their own terms and their own citations.
- The artifact family has the substring problem the lexicon just lost:
  `pin_request` fires on an advisory that says "never share your PIN". The
  impersonation hard-zero on official domains covers the common case, but a
  lookalike domain hosting copied advisory text still scores.
- Counter terms are a blunt instrument — they subtract wherever they appear, not
  only where they signal commentary. Check `lexicon_hits` in the breakdown when
  a score looks wrong.

## Compliance

This collects and stores data about identifiable people. Before running it
against live traffic in an employer context, confirm the lawful basis, whether a
DPIA is required, retention limits, and who may access the queue. Do not join
findings to internal customer records without that sign-off.
