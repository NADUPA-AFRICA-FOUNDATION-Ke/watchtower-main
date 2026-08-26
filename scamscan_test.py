"""scamscan tests. No network, no API key, no cost.

The three checks that matter here are all about the same thing: a query that
never ran must never be reported as a query that found nothing. Scam discovery
inverts the usual bias — an empty queue is read as "this brand is clean", so a
silent failure is a false negative someone acts on.

    python scamscan_test.py
"""

import io
import json
import os
import sqlite3
import sys
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

# scamscan.py loads .env at import, so without this the suite would take the
# Gemini path on a machine with a Gemini key and the Anthropic path on one
# without — passing or failing depending on whose laptop it runs on. The
# provider-specific behaviour is covered by its own section below, which sets
# the variables it needs and restores them.
os.environ["SCAMSCAN_PROVIDER"] = "anthropic"
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key-not-used-offline")

from scamscan import (DYNAMIC_FILTERING_MODELS, FINDINGS_SCHEMA,
                      QUERIES_SCHEMA, WEB_SEARCH_BASIC, WEB_SEARCH_DYNAMIC,
                      HuntError, RunState, db_connect, expand_queries,
                      extract_artifacts, hunt,
                      fingerprint, hunt_query, impersonation_score,
                      lexicon_score, lint_schema, parse_json_array,
                      parse_payload, registrable, score_finding,
                      grounding_failures, model_for, provider,
                      search_failures, structured_rejected, term_pattern,
                      term_weight, web_search_tool)
import osint_discovery
from osint_discovery import discover_and_score, evaluate_url, select_queries

CFG = json.load(open(Path(__file__).parent / "config.json"))


def check(label, cond):
    print(f"  {'PASS' if cond else 'FAIL'}  {label}")
    return bool(cond)


def quiet(fn, *a, **kw):
    """Run something that prints a downgrade notice, and keep the output."""
    buf = io.StringIO()
    with redirect_stdout(buf):
        result = fn(*a, **kw)
    return result, buf.getvalue()


# --- stand-ins for the SDK's response objects -----------------------------

class Block:
    def __init__(self, type, **kw):
        self.type = type
        for k, v in kw.items():
            setattr(self, k, v)


class Err:
    def __init__(self, error_code):
        self.type = "web_search_tool_result_error"
        self.error_code = error_code


class Resp:
    def __init__(self, content, stop_reason="end_turn"):
        self.content = content
        self.stop_reason = stop_reason


class ApiError(Exception):
    """Stands in for anthropic.BadRequestError etc — only status_code is read."""

    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.status_code = status_code


class FakeClient:
    """Replays scripted responses and records the request kwargs it was sent."""

    def __init__(self, *script):
        self.script = list(script)
        self.requests = []
        self.messages = self

    def create(self, **kw):
        self.requests.append(kw)
        item = self.script.pop(0) if self.script else Resp([Block("text", text="{}")])
        if isinstance(item, Exception):
            raise item
        return item


def text_resp(payload, stop_reason="end_turn", search=True):
    blocks = []
    if search:
        blocks.append(Block("web_search_tool_result", content=[{"url": "https://x"}]))
    blocks.append(Block("text", text=json.dumps(payload)))
    return Resp(blocks, stop_reason)


FINDING = {"url": "http://mpesa-verify.co.ke/login", "title": "verify",
           "scam_type": "phishing", "summary": "send your pin",
           "quoted_evidence": "send your pin", "model_confidence": 0.8}


def main():
    ok = True

    print("\nartifact extraction")
    a = extract_artifacts("Send your PIN. Paybill 247247. wa.me/254712345678")
    ok &= check("finds a PIN request", "pin_request" in a)
    ok &= check("finds a paybill", "paybill" in a)
    ok &= check("finds a WhatsApp link", "whatsapp" in a)
    ok &= check("clean text yields nothing",
                extract_artifacts("Our branches open at 9am.") == {})

    print("\nimpersonation")
    ok &= check("an official domain is hard-zeroed",
                impersonation_score("https://safaricom.co.ke/help", CFG["brand"])[0] == 0)
    ok &= check("a lookalike host scores",
                impersonation_score("http://mpesa-verify.co.ke/login", CFG["brand"])[0] > 0)
    ok &= check("east african eTLD+1 is handled",
                registrable("www.foo.bar.co.ke") == "bar.co.ke")
    ok &= check("homoglyph folding catches cyrillic",
                impersonation_score("http://ѕafaricom-login.com", CFG["brand"])[0] > 0)
    ok &= check("short aliases do not match inside unrelated hostnames",
                impersonation_score("https://safety.example", CFG["brand"])[0] == 0)
    ok &= check("short aliases still match as a deliberate DNS label",
                impersonation_score("https://kcb.login.example", CFG["brand"])[0] > 0)

    print("\nhost infrastructure ratings")
    hosted = {"url": "fuliza-limit.vercel.app", "summary": ""}
    hosted_score = score_finding(hosted, CFG)
    ok &= check("bare hosts are rated the same as fully qualified URLs",
                hosted_score == score_finding({**hosted,
                                                "url": "https://fuliza-limit.vercel.app"}, CFG))
    ok &= check("a real free-host suffix is recorded",
                hosted_score["infrastructure_flags"] == {"on_free_host": True})
    ok &= check("a lookalike suffix is not treated as free hosting",
                not score_finding({"url": "https://fuliza-vercel.app.evil.example"},
                                  CFG)["infrastructure_flags"])

    print("\nOSINT candidate quality")
    generated = osint_discovery.generate_queries(CFG, "fuliza")
    lexicon_queries = [q for q in generated if '("' in q]
    ok &= check("sourced lexicon phrases drive OSINT searches",
                lexicon_queries
                and any("namba ya siri" in q for q in lexicon_queries)
                and not any("increase your limit" in q for q in lexicon_queries)
                and not any("*locked*" in q for q in lexicon_queries))
    chosen = select_queries([
        'site:vercel.app "fuliza"',
        'site:netlify.app "fuliza"',
        'site:vercel.app "fuliza" loan',
        '"fuliza" "processing fee"',
        'inurl:fuliza inurl:login',
        '"fuliza" ("namba ya siri")',
    ])
    ok &= check("query budget covers each discovery family",
                any(q.startswith("site:") and q.endswith('"fuliza"') for q in chosen)
                and any(" loan" in q for q in chosen)
                and any("processing fee" in q for q in chosen)
                and any(q.startswith("inurl:") for q in chosen)
                and any('(\"namba ya siri\")' in q for q in chosen))
    snippet_score = evaluate_url("https://offers.example", "Fuliza offer",
                                 "Pay a processing fee to activate", CFG)
    ok &= check("search snippets contribute to OSINT risk ratings",
                snippet_score["lexicon_score"] > 0)
    original_search = osint_discovery.search_duckduckgo
    original_brand = json.loads(json.dumps(CFG["brand"]))
    try:
        osint_discovery.search_duckduckgo = lambda query, max_results=10: [{
            "url": "https://fuliza-offer.example",
            "title": "Fuliza activation",
            "summary": "Pay a processing fee to activate",
            "source": "test-search",
        }]
        discovered = discover_and_score("fuliza", 1, CFG)
    finally:
        osint_discovery.search_duckduckgo = original_search
    ok &= check("discovery keeps the snippet and explainable breakdown",
                discovered[0]["summary"]
                and discovered[0]["breakdown"]["lexicon_score"] > 0)
    ok &= check("one brand search does not mutate later searches",
                CFG["brand"] == original_brand)

    print("\nlexicon")
    hits, _ = lexicon_score("guaranteed returns, double your money", CFG["lexicon"])
    ok &= check("weighted multilingual terms accumulate", hits > 0)
    ok &= check("swahili terms are scored",
                lexicon_score("namba ya siri", CFG["lexicon"])[0] > 0)
    ok &= check("score is capped at 100",
                lexicon_score(" ".join(CFG["lexicon"]["en"]), CFG["lexicon"])[0] <= 100)

    print("\nreal terms need word boundaries, not substrings")
    # Each of these fires under `term in text` and is pure noise. They are the
    # reason a lexicon rebuilt from real cases needs the matcher rebuilt too.
    for text, term in (("international adoption agency", "otp"),
                       ("irreversible damage", "reversal"),
                       ("please contact nowhere else", "act now")):
        ok &= check(f"{term!r} does not fire inside {text!r}",
                    not term_pattern(term).search(text))
    ok &= check("but a real occurrence still matches",
                bool(term_pattern("otp").search("Share the OTP with nobody")))
    ok &= check("and a term matches across a line break",
                bool(term_pattern("send your pin").search("send\nyour   pin")))
    ok &= check("a term whose edges are punctuation still matches",
                bool(term_pattern("*locked*").search("balance is Ksh(*LOCKED*).")))

    print("\nevery scoring term is traceable to a source")
    unsourced = [f"{lang}:{t}" for lang, group in CFG["lexicon"].items()
                 for t, entry in group.items() if not term_weight(entry)[1]]
    ok &= check(f"no term ships without provenance ({unsourced[:3]})", not unsourced)
    ok &= check("a bare number is still a valid entry", term_weight(22) == (22.0, ""))
    ok &= check("so is [weight, source]", term_weight([22, "DCI"]) == (22.0, "DCI"))
    ok &= check("so is {weight, source}",
                term_weight({"weight": 22, "source": "DCI"}) == (22.0, "DCI"))
    ok &= check("the source reaches the hit list, so a score can be defended",
                "[COMPASS2025]" in lexicon_score("pay to POCHI today",
                                                 CFG["lexicon"])[1][0])

    print("\nanti-fraud pages quote the bait, so counter terms must pull them down")
    advisory = ("Never share your PIN. Safaricom will never ask for your M-PESA "
                "PIN. If you receive a message claiming your SIM card has been "
                "registered twice, report it. Fraud awareness.")
    raw = lexicon_score(advisory, CFG["lexicon"])[0]
    damped = lexicon_score(advisory, CFG["lexicon"], CFG["counter_terms"])[0]
    ok &= check("the advisory scores high on terms alone", raw >= 80)
    ok &= check("and near zero once counter terms apply", damped < 20)
    ok &= check("the real scam sample is untouched by them",
                lexicon_score("New M-PESA balance is Ksh(*LOCKED*). Pay to POCHI",
                              CFG["lexicon"], CFG["counter_terms"])[0] >= 80)
    ok &= check("scores never go negative",
                lexicon_score("never share your pin", CFG["lexicon"],
                              CFG["counter_terms"])[0] == 0)
    ok &= check("score_finding applies them without being asked",
                score_finding({"url": "https://www.safaricom.co.ke/fraud-awareness",
                               "summary": advisory}, CFG)["lexicon_score"] < 20)

    print("\ndedupe")
    a1 = {"url": "https://scam.example/a", "summary": "Send your pin now to win"}
    a2 = {"url": "https://scam.example/b", "summary": "Send your pin now to win"}
    b1 = {"url": "https://other.example/a", "summary": "Send your pin now to win"}
    ok &= check("same site + same copy collapses",
                fingerprint(a1) == fingerprint(a2))
    ok &= check("different site stays separate — cross-site reuse is signal",
                fingerprint(a1) != fingerprint(b1))

    print("\na missing model_confidence must not silently demote a finding")
    strong = {"url": "http://mpesa-verify.co.ke/login",
              "title": "verify", "quoted_evidence": "send your pin",
              "summary": "guaranteed returns, double your money. Paybill 247247"}
    without = score_finding(dict(strong), CFG)
    with_conf = score_finding({**strong, "model_confidence": 0.9}, CFG)
    zeroed = score_finding({**strong, "model_confidence": 0.0}, CFG)

    ok &= check("absent confidence is excluded, not scored as zero",
                without["score"] > zeroed["score"])
    ok &= check("and the run records which families it scored on",
                "model" not in without["scored_on"]
                and "model" in with_conf["scored_on"])
    ok &= check("an explicit 0.0 still counts against the finding",
                zeroed["model_score"] == 0.0)
    # The precise property: average over the families that reported, so the
    # score is the mean of three, not of three plus a phantom zero.
    local_mean = round((without["lexicon_score"] + without["artifact_score"]
                        + without["impersonation_score"]) / 3, 1)
    ok &= check("the score is the mean of the families that reported",
                without["score"] == local_mean)
    ok &= check("which is worth ~25% of the range on this fixture",
                without["score"] - (local_mean * 3 / 4) > 15)
    ok &= check("a malformed confidence is ignored, not crashed on",
                isinstance(score_finding({**strong, "model_confidence": "n/a"},
                                         CFG)["score"], float))
    ok &= check("scores stay within 0-100",
                0 <= score_finding({**strong, "model_confidence": 9.9},
                                   CFG)["score"] <= 100)

    print("\na failed web search must not look like a clean brand")
    # The API reports these as HTTP 200 with an error object in the result
    # block — nothing raises, so they have to be detected explicitly.
    for code in ("max_uses_exceeded", "too_many_requests", "unavailable"):
        resp = Resp([Block("web_search_tool_result", content=Err(code)),
                     Block("text", text="[]")])
        ok &= check(f"{code} is detected", search_failures(resp) == [code])

    good = Resp([Block("web_search_tool_result", content=[{"url": "https://x"}]),
                 Block("text", text="[]")])
    ok &= check("a successful search reports no failure", search_failures(good) == [])
    ok &= check("a response with no search block is not a failure",
                search_failures(Resp([Block("text", text="[]")])) == [])

    print("\nweb search tool version follows the model, not a constant")
    def tool_for(model, **extra):
        cfg = {**CFG, "search": {**CFG["search"], "model": model, **extra}}
        return web_search_tool(cfg)

    ok &= check("configured model gets dynamic filtering",
                tool_for(CFG["search"]["model"])[0]["type"] == WEB_SEARCH_DYNAMIC)
    for model in DYNAMIC_FILTERING_MODELS:
        if tool_for(model)[0]["type"] != WEB_SEARCH_DYNAMIC:
            ok &= check(f"{model} should get dynamic filtering", False)
            break
    else:
        ok &= check("every listed family gets the _20260209 tool", True)
    ok &= check("a model without it falls back instead of 400ing",
                tool_for("claude-haiku-4-5-20251001")[0]["type"] == WEB_SEARCH_BASIC)
    ok &= check("and the fallback says why",
                "claude-haiku" in tool_for("claude-haiku-4-5-20251001")[1])
    ok &= check("an explicit pin overrides the model check",
                tool_for("claude-haiku-4-5-20251001",
                         web_search_tool_version=WEB_SEARCH_DYNAMIC)[0]["type"]
                == WEB_SEARCH_DYNAMIC)
    ok &= check("location and blocklist still ride along",
                tool_for(CFG["search"]["model"])[0]["blocked_domains"]
                == CFG["search"]["blocked_domains"])

    print("\nschemas obey the documented output_config.format restrictions")
    ok &= check("findings schema lints clean", lint_schema(FINDINGS_SCHEMA) == [])
    ok &= check("queries schema lints clean", lint_schema(QUERIES_SCHEMA) == [])
    ok &= check("a top-level array is rejected",
                lint_schema({"type": "array"}) != [])
    ok &= check("a missing additionalProperties is caught",
                lint_schema({"type": "object", "properties": {}}) != [])
    ok &= check("an unsupported keyword is caught",
                lint_schema({"type": "object", "additionalProperties": False,
                             "properties": {"n": {"type": "number", "minimum": 0}}}) != [])
    ok &= check("the schema requires model_confidence, removing the omission",
                "model_confidence" in
                FINDINGS_SCHEMA["properties"]["findings"]["items"]["required"])

    print("\nparsing")
    ok &= check("tolerates markdown fences",
                parse_json_array('```json\n[{"url": "x"}]\n```') == [{"url": "x"}])
    ok &= check("tolerates surrounding prose",
                len(parse_json_array('Here you go: [{"url": "x"}] hope that helps')) == 1)
    ok &= check("malformed JSON yields empty rather than raising",
                parse_json_array("[{oops") == [])
    ok &= check("HuntError is distinct from a generic failure",
                issubclass(HuntError, Exception)
                and HuntError is not Exception)

    print("\nunder a schema, a bad parse is a broken contract, not an empty result")
    ok &= check("a conforming payload reads back",
                parse_payload('{"findings": [{"url": "x"}]}', "findings", True)
                == [{"url": "x"}])
    for bad, label in (("not json at all", "non-JSON"),
                       ('{"other": []}', "wrong key"),
                       ('{"findings": "nope"}', "wrong type")):
        try:
            parse_payload(bad, "findings", True)
            ok &= check(f"{label} must raise, not return []", False)
        except HuntError:
            ok &= check(f"{label} raises HuntError", True)
    ok &= check("without a schema the tolerant path still salvages an object",
                parse_payload('```json\n{"findings": [{"url": "x"}]}\n```',
                              "findings", False) == [{"url": "x"}])
    ok &= check("and a bare array, which models still emit in text mode",
                parse_payload('[{"url": "x"}]', "findings", False) == [{"url": "x"}])

    print("\nonly a structured-output 400 may downgrade the run")
    ok &= check("a 400 naming output_config is recognised",
                structured_rejected(ApiError("output_config not supported with tools")))
    ok &= check("so is one naming json_schema",
                structured_rejected(ApiError("json_schema is unsupported here")))
    ok &= check("a credit-balance 400 must keep propagating",
                not structured_rejected(ApiError("Your credit balance is too low")))
    ok &= check("a 429 is not a schema problem",
                not structured_rejected(ApiError("rate limited", status_code=429)))
    ok &= check("neither is an exception with no status",
                not structured_rejected(ValueError("boom")))

    print("\nhunt_query sends a schema, and downgrades visibly if refused")
    state = RunState()
    client = FakeClient(text_resp({"findings": [FINDING]}))
    found = hunt_query(client, CFG, "q", state)
    sent = client.requests[0]
    ok &= check("the request carries output_config.format",
                sent["output_config"]["format"]["type"] == "json_schema")
    ok &= check("and the _20260209 web search tool",
                sent["tools"][0]["type"] == WEB_SEARCH_DYNAMIC)
    ok &= check("the prompt drops the 'return only JSON' boilerplate",
                "markdown fences" not in sent["messages"][0]["content"])
    ok &= check("findings come back", len(found) == 1)

    state = RunState()
    client = FakeClient(ApiError("output_config is not supported with server tools"),
                        text_resp({"findings": [FINDING]}))
    found, out = quiet(hunt_query, client, CFG, "q", state)
    ok &= check("a rejection retries without the schema",
                "output_config" not in client.requests[1])
    ok &= check("and re-adds the JSON instruction the schema replaced",
                "markdown fences" in client.requests[1]["messages"][0]["content"])
    ok &= check("the downgrade is printed, not swallowed",
                "falling back" in out)
    ok &= check("and remembered so the next query does not re-pay for the 400",
                state.structured_disabled is not None)
    ok &= check("results still come back", len(found) == 1)

    state = RunState()
    client = FakeClient(ApiError("Your credit balance is too low"))
    try:
        hunt_query(client, CFG, "q", state)
        ok &= check("an unrelated 400 must not be treated as a downgrade", False)
    except ApiError:
        ok &= check("an unrelated 400 propagates instead of downgrading", True)

    print("\nthe silent zeros stay closed on the structured path")
    state = RunState()
    client = FakeClient(Resp([Block("text", text='{"findings": []}')], "refusal"))
    try:
        hunt_query(client, CFG, "q", state)
        ok &= check("a refusal must raise", False)
    except HuntError:
        ok &= check("a refusal still raises before the payload is read", True)

    state = RunState()
    client = FakeClient(Resp([Block("web_search_tool_result",
                                    content=Err("too_many_requests")),
                              Block("text", text='{"findings": []}')]))
    try:
        hunt_query(client, CFG, "q", state)
        ok &= check("a failed search must raise", False)
    except HuntError:
        ok &= check("a failed search still raises", True)

    state = RunState()
    client = FakeClient(text_resp({"findings": [FINDING]}, stop_reason="pause_turn"))
    events = []
    found = hunt_query(client, CFG, "q", state, events.append)
    ok &= check("a paused turn returns its partial results", len(found) == 1)
    ok &= check("and reports through progress() that they are partial",
                any(e["type"] == "note" and "partial" in e["message"]
                    for e in events))

    print("\nhunt() reports as it goes, so the CLI and the web layer agree")
    script = [Resp([Block("text", text='{"queries": ["a", "b"]}')]),
              text_resp({"findings": [FINDING]}),
              Resp([Block("web_search_tool_result", content=Err("too_many_requests")),
                    Block("text", text='{"findings": []}')])]
    con = sqlite3.connect(":memory:")
    events = []
    summary = hunt(FakeClient(*script), CFG, db_connect(":memory:"), 1, events.append)
    kinds = [e["type"] for e in events]
    ok &= check("it opens with what the run is about to do", kinds[0] == "start")
    ok &= check("and closes with exactly one done", kinds.count("done") == 1)
    ok &= check("topics, queries and findings each get an event",
                {"topic", "query", "finding"} <= set(kinds))
    ok &= check("a query that never searched is 'unsearched', not 'failed'",
                "unsearched" in kinds and "failed" not in kinds)
    ok &= check("the summary counts only the queries that ran",
                summary["queries_run"] == 1 and len(summary["failures"]) == 1)
    ok &= check("and refuses to call the run complete", summary["complete"] is False)
    clean = hunt(FakeClient(Resp([Block("text", text='{"queries": ["a"]}')]),
                            text_resp({"findings": [FINDING]})),
                 CFG, db_connect(":memory:"), 1)
    ok &= check("a run where everything searched is complete",
                clean["complete"] is True and not clean["failures"])
    con.close()

    print("\ngemini: the silent zero has a different shape and must still close")
    # Anthropic reports a failed search as an error object inside a 200. Gemini
    # just answers from memory and the only evidence is negative — no grounding
    # metadata. That is a query that never ran, not a clean brand.
    class GMeta:
        def __init__(self, queries=None, chunks=None):
            self.web_search_queries = queries
            self.grounding_chunks = chunks

    class GCand:
        def __init__(self, finish="STOP", meta=None):
            self.finish_reason = finish
            self.grounding_metadata = meta

    class GFeedback:
        def __init__(self, reason=None):
            self.block_reason = reason

    class GResp:
        def __init__(self, candidates, feedback=None, text='{"findings": []}'):
            self.candidates = candidates
            self.prompt_feedback = feedback
            self.text = text

    grounded = GResp([GCand(meta=GMeta(queries=["mpesa scam"]))])
    ok &= check("a grounded answer reports no failure",
                grounding_failures(grounded) == [])
    ok &= check("an ungrounded answer to a search query is a failure",
                grounding_failures(GResp([GCand(meta=GMeta())])) != [])
    ok &= check("and names what actually went wrong",
                "without searching" in grounding_failures(GResp([GCand()]))[0])
    ok &= check("a safety stop is a failure, not an empty result",
                grounding_failures(GResp([GCand(finish="SAFETY",
                                                meta=GMeta(["q"]))])) != [])
    ok &= check("a blocked prompt is caught before the text is read",
                grounding_failures(GResp([GCand(meta=GMeta(["q"]))],
                                         GFeedback("PROHIBITED_CONTENT"))) != [])
    ok &= check("no candidates at all is a failure", grounding_failures(GResp([])) != [])
    # Expansion runs without the search tool, so ungrounded is correct there.
    ok &= check("a toolless call is not expected to be grounded",
                grounding_failures(GResp([GCand()]), expected_search=False) == [])

    print("\na dry run must never be mistaken for a hunt that found nothing")
    client = FakeClient(Resp([Block("text", text='{"queries": ["a", "b"]}')]),
                        text_resp({"findings": [FINDING]}))
    con2 = db_connect(":memory:")
    events = []
    dry = hunt(client, CFG, con2, 1, events.append, dry_run=True)
    kinds = [e["type"] for e in events]
    ok &= check("it expands topics into queries", kinds.count("query") == 2)
    ok &= check("but never searches", "finding" not in kinds)
    ok &= check("only the expansion call is made", len(client.requests) == 1)
    ok &= check("nothing is written to the database",
                con2.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0)
    # The whole reason it is safe: complete=False means no caller can render
    # this as "searched the brand, found nothing".
    ok &= check("the run is not complete", dry["complete"] is False)
    ok &= check("and says plainly that it was a dry run", dry["dry_run"] is True)
    ok &= check("a real run still stores and completes",
                hunt(FakeClient(Resp([Block("text", text='{"queries": ["a"]}')]),
                                text_resp({"findings": [FINDING]})),
                     CFG, db_connect(":memory:"), 1)["complete"] is True)
    con2.close()

    print("\nthinking tokens are billed against the output budget on gemini")
    # Expansion asked for 800 tokens, Gemini 3 spent them thinking, and the
    # JSON came back truncated mid-string. Thinking off is the fix, and the
    # request has to actually carry it.
    src = Path(__file__).parent.joinpath("scamscan.py").read_text()
    ok &= check("expansion disables thinking", "thinking_budget=0" in src)
    ok &= check("and hunt gives itself headroom instead",
                "max_tokens=8000 if provider(cfg) == \"gemini\"" in src)

    print("\nthe suite pins a provider so it does not depend on local keys")
    ok &= check("pinned to anthropic for the deterministic sections",
                provider({}) == "anthropic")

    print("\nprovider selection follows the key that is actually set")
    saved = {k: os.environ.get(k) for k in ("GEMINI_API_KEY", "ANTHROPIC_API_KEY",
                                            "SCAMSCAN_PROVIDER")}
    try:
        for k in saved:
            os.environ.pop(k, None)
        ok &= check("no key means no provider, rather than a crash", provider({}) == "")
        os.environ["ANTHROPIC_API_KEY"] = "a"
        ok &= check("anthropic alone is picked", provider({}) == "anthropic")
        os.environ["GEMINI_API_KEY"] = "g"
        ok &= check("gemini wins when both are set — it has the free tier",
                    provider({}) == "gemini")
        ok &= check("config can force the other way",
                    provider({"search": {"provider": "anthropic"}}) == "anthropic")
        ok &= check("and the model follows the provider",
                    model_for({"search": {"provider": "anthropic",
                                          "model": "claude-x"}}) == "claude-x")
        ok &= check("a gemini 400 about response_schema still downgrades",
                    structured_rejected(
                        ApiError("response_json_schema is not supported with tools")))
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    print("\nexpansion has no web search, so an empty result is never legitimate")
    state = RunState()
    client = FakeClient(Resp([Block("text", text='{"queries": ["a", "b", "c"]}')]))
    ok &= check("queries parse from the schema wrapper",
                expand_queries(client, CFG, "topic", state) == ["a", "b", "c"])
    ok &= check("expansion is capped at queries_per_topic",
                len(expand_queries(
                    FakeClient(Resp([Block("text",
                                           text='{"queries": ["a","b","c","d","e"]}')])),
                    CFG, "topic", RunState()))
                == CFG["search"]["queries_per_topic"])
    try:
        expand_queries(FakeClient(Resp([Block("text", text='{"queries": []}')])),
                       CFG, "topic", RunState())
        ok &= check("an empty expansion must raise", False)
    except HuntError:
        ok &= check("an empty expansion raises instead of zeroing the topic", True)

    print("\n" + ("ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED") + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
