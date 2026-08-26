"""Offline smoke test. No network, no API key. Proves the pipeline wiring works.

    python smoke_test.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core import alerts
from core.clean import extract, truncate
from core.models import Item
from core.store import Store

SAMPLE_HTML = """
<html><head><title>Regulator fines bank over AML failings</title></head>
<body>
  <nav><a href="/">Home</a><a href="/news">News</a></nav>
  <article>
    <h1>Regulator fines bank over AML failings</h1>
    <p>The Central Bank of Kenya has imposed a penalty on a commercial bank
    after a review found weaknesses in its transaction monitoring and
    beneficial ownership verification controls.</p>
    <p>The review covered correspondent banking relationships across three
    markets and flagged gaps in escalation procedures.</p>
  </article>
  <footer>Copyright 2026. Subscribe to our newsletter!</footer>
</body></html>
"""

WATCHLIST = ["Central Bank of Kenya", "beneficial ownership",
             "correspondent banking", "nonexistent term"]


def check(label, condition):
    print(f"  {'PASS' if condition else 'FAIL'}  {label}")
    return condition


def main():
    ok = True
    db = Path("smoke.db")
    db.unlink(missing_ok=True)

    print("\nclean.extract")
    cleaned = extract(SAMPLE_HTML, "https://example.org/a")
    ok &= check("pulls the title", "AML failings" in cleaned["title"])
    ok &= check("pulls body text", "Central Bank of Kenya" in cleaned["text"])
    ok &= check("strips nav", "Home" not in cleaned["text"])
    ok &= check("strips footer", "Subscribe" not in cleaned["text"])
    ok &= check("truncate caps length", len(truncate("x " * 5000, 100)) < 130)

    print("\nmodels.Item")
    a = Item(url="https://a.com/1", source="rss:test", source_type="news",
             title=cleaned["title"], text=cleaned["text"])
    b = Item(url="https://b.com/9", source="rss:other", source_type="news",
             title=cleaned["title"], text=cleaned["text"])
    c = Item(url="https://c.com/3", source="rss:test", source_type="news",
             title="Unrelated sports result", text="A football match ended 2-1.")
    ok &= check("same story at two URLs shares a hash",
                a.content_hash == b.content_hash)
    ok &= check("different story differs", a.content_hash != c.content_hash)

    print("\nstore")
    s = Store(db)
    n1 = s.add([a, b, c])
    n2 = s.add([a, b, c])
    ok &= check(f"deduped syndicated copy on insert (got {n1}, want 2)", n1 == 2)
    ok &= check("re-running inserts nothing new", n2 == 0)
    ok &= check("seen_urls round-trips", (s.mark_seen(["https://a.com/1"], "t", "now")
                                          or s.is_seen("https://a.com/1")))
    ok &= check("stats report correctly", s.stats()["total"] == 2)

    print("\nsearch (FTS5)")
    hits = s.search("laundering OR monitoring")
    ok &= check("finds by body term", len(hits) == 1)
    ok &= check('phrase search works', len(s.search('"beneficial ownership"')) == 1)
    ok &= check("no false positives", len(s.search("volcano")) == 0)

    print("\nalerts")
    s.save_enrichment(a.content_hash, "Regulator penalised a bank.",
                      ["Central Bank of Kenya"], ["enforcement action"], 85)
    s.save_enrichment(c.content_hash, "A football result.", [], [], 4)
    selected = alerts.select(s, WATCHLIST, min_relevance=60)
    ok &= check("flags the relevant item only", len(selected) == 1)
    ok &= check("records both triggers",
                selected[0]["triggered_by"] == "keyword+model")
    ok &= check("whole-word matching avoids the decoy",
                "nonexistent term" not in selected[0]["keyword_hits"])
    ok &= check("caught all three real terms",
                len(selected[0]["keyword_hits"]) == 3)

    rendered = alerts.render(selected, brief="")
    ok &= check("digest renders", "1 new item(s) matched" in rendered)
    s.mark_alerted([x["content_hash"] for x in selected])
    ok &= check("alerted items don't repeat",
                len(alerts.select(s, WATCHLIST, 60)) == 0)

    s.close()
    db.unlink(missing_ok=True)

    print("\nadapters — scheduled mode collection")
    import httpx

    from adapters import gdelt as ad_gdelt
    from adapters import rss as ad_rss
    from adapters import social as ad_social
    from adapters import webpage as ad_webpage
    from core.fetch import Fetcher

    FEED = """<?xml version="1.0"?><rss version="2.0"><channel>
      <title>CBK</title>
      <item><title>Bank fined over AML failings</title>
        <link>https://reg.example/a</link>
        <pubDate>Wed, 12 Aug 2026 09:00:00 GMT</pubDate>
        <description>&lt;p&gt;A penalty was imposed.&lt;/p&gt;</description></item>
      <item><title>Second notice</title><link>https://reg.example/b</link></item>
    </channel></rss>"""
    LISTING = """<html><body>
      <a href="/press-release/one">First circular</a>
      <a href="/notice/two.pdf">A PDF circular</a>
      <a href="/about">About us</a>
      <a href="https://elsewhere.example/press-release/x">Offsite</a>
    </body></html>"""
    GDELT_JSON = ('{"articles":[{"url":"https://news.example/1","title":"Story",'
                  '"seendate":"20260812T090000Z","domain":"news.example",'
                  '"sourcecountry":"Kenya","language":"English"}]}')

    def handler(request):
        u = str(request.url)
        if u.endswith("/robots.txt"):
            return httpx.Response(200, text="User-agent: *\nAllow: /")
        if "feed" in u:
            return httpx.Response(200, text=FEED,
                                  headers={"content-type": "application/rss+xml"})
        if "gdeltproject" in u:
            return httpx.Response(200, text=GDELT_JSON,
                                  headers={"content-type": "application/json"})
        if u.endswith("/listing"):
            return httpx.Response(200, text=LISTING,
                                  headers={"content-type": "text/html"})
        if u.endswith(".pdf"):
            return httpx.Response(200, content=b"%PDF-1.4 not a real pdf",
                                  headers={"content-type": "application/pdf"})
        return httpx.Response(200, text=SAMPLE_HTML,
                              headers={"content-type": "text/html"})

    fetcher = Fetcher(user_agent="test", delay=0.0,
                      transport=httpx.MockTransport(handler))
    s2 = Store(":memory:")

    items = ad_rss.collect("https://reg.example/feed", "cbk", "regulatory",
                           fetcher, s2, fetch_body=True, limit=10)
    ok &= check("rss returns both entries", len(items) == 2)
    ok &= check("rss names the source it came from", items[0].source == "rss:cbk")
    ok &= check("rss parses the date to ISO",
                items[0].published_at.startswith("2026-08-12T09:00"))
    ok &= check("rss fetches the article body",
                "transaction monitoring" in items[0].text)
    # A dateless entry may legitimately inherit the article page's date, so the
    # property to test is that nothing invents one when there is no page to read.
    headline_only = ad_rss.collect("https://reg.example/feed", "cbk", "regulatory",
                                   fetcher, Store(":memory:"), fetch_body=False)
    ok &= check("an entry with no date does not get today's date",
                headline_only[1].published_at == "")
    ok &= check("and no body is fetched when fetch_body is off",
                headline_only[0].text == "A penalty was imposed.")

    # The point of scheduled mode: the second poll of an unchanged feed is free.
    s2.add(items)
    s2.mark_seen([i.url for i in items], "rss:cbk", "2026-08-12")
    ok &= check("a second poll returns nothing already seen",
                ad_rss.collect("https://reg.example/feed", "cbk", "regulatory",
                               fetcher, s2, fetch_body=True) == [])

    g = ad_gdelt.collect("money laundering", fetcher, Store(":memory:"))
    ok &= check("gdelt returns articles", len(g) == 1)
    ok &= check("gdelt normalises its own date format",
                g[0].published_at == "2026-08-12T09:00:00+00:00")
    errs = []
    ad_gdelt.collect("q", fetcher, Store(":memory:"), errors=errs)
    ok &= check("gdelt does not raise on a good response", errs == [])

    w = ad_webpage.collect("https://reg.example/listing", "reg", fetcher,
                           Store(":memory:"),
                           link_pattern=r"/press-release|/notice|\.pdf$")
    urls = [i.url for i in w]
    ok &= check("webpage keeps links matching the pattern", len(w) == 2)
    ok &= check("and drops ones that do not",
                not any("/about" in u for u in urls))
    # Off-site links on a regulator page are navigation, never the circular.
    ok &= check("and drops off-site links",
                not any("elsewhere.example" in u for u in urls))
    pdf = next(i for i in w if i.url.endswith(".pdf"))
    ok &= check("a PDF is recognised as one", pdf.raw_meta.get("format") == "pdf")
    # An unreadable PDF must explain itself: empty text here would otherwise be
    # indistinguishable from a circular that said nothing.
    ok &= check("an unreadable PDF says why it is empty",
                bool(pdf.raw_meta.get("extract_note")) or bool(pdf.text))
    ok &= check("a bad link_pattern is reported, not raised",
                ad_webpage.collect("https://reg.example/listing", "reg", fetcher,
                                   Store(":memory:"), link_pattern="(", errors=errs) == []
                and any("link_pattern" in e for e in errs))

    ok &= check("reddit reports missing credentials instead of returning a silent []",
                ad_social.collect_reddit(["kenya"], Store(":memory:"), errors=(e2 := [])) == []
                and any("REDDIT_CLIENT_ID" in x for x in e2))
    ok &= check("RETENTION_DAYS is set and enforced by purge_expired",
                ad_social.RETENTION_DAYS > 0
                and callable(ad_social.purge_expired))

    print("\nretention actually deletes, including from the search index")
    from datetime import datetime, timedelta, timezone
    s3 = Store(":memory:")
    stale = (datetime.now(timezone.utc)
             - timedelta(days=ad_social.RETENTION_DAYS + 5)).isoformat()
    old = Item(url="https://reddit.example/old", source="reddit:x",
               source_type="social", title="old post laundering", text="body")
    old.fetched_at = stale
    recent = Item(url="https://reddit.example/new", source="reddit:x",
                  source_type="social", title="recent post laundering", text="body")
    news = Item(url="https://n.example/1", source="rss:n", source_type="news",
                title="old news laundering", text="body")
    news.fetched_at = stale
    s3.add([old, recent, news])
    ok &= check("the expired social item is purged", ad_social.purge_expired(s3) == 1)
    titles = [r["title"] for r in s3.search("laundering")]
    # The FTS index is a second copy of the text. Deleting the row without
    # deleting the index leaves the post findable — a retention limit that
    # only half applies is not one.
    ok &= check("and is gone from FTS, not just from the table",
                not any("old post" in t for t in titles))
    ok &= check("a recent social item survives",
                any("recent post" in t for t in titles))
    ok &= check("retention applies to social only, not to news",
                any("old news" in t for t in titles))
    fetcher.close()

    print("\n" + ("ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED") + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
