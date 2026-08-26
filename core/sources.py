"""Keyword-searchable sources that need no API key and no scraping.

Every backend here takes a query string and returns list[Item]. All of them are
public APIs or published feeds, so there's no ToS grey area and nothing to
maintain when a site redesigns.

  gdelt          global news, all languages, 15-min lag, back to 2017
  google_news    broad news via the published RSS search endpoint
  web_search     the whole indexed web, via Brave       (BRAVE_API_KEY)
  wikipedia      entity background and disambiguation
  hackernews     via Algolia's public API; tech and fintech chatter
  mastodon       public post search on any instance that allows it
  bluesky        public post search over the AT Protocol, no key
  reddit         official OAuth API   (REDDIT_CLIENT_ID/REDDIT_CLIENT_SECRET)
  x              X/Twitter recent search, official paid API (X_BEARER_TOKEN)
  gleif          Legal Entity Identifiers, free, no key
  opencorporates company registries      (OPENCORPORATES_API_KEY)
  sec_edgar      US filings full-text, useful for company checks
  opensanctions  sanctions/PEP/watchlist matching (OPENSANCTIONS_API_KEY)

Scraped platforms are absent on purpose — see CLAUDE.md. X is here *only*
through its official paid API: a documented endpoint with a contract behind it
fails loudly, where a scraper returns an empty list and calls it coverage.
ICIJ Offshore Leaks is deliberately not here: it publishes no API, and the
only way in would be scraping the search UI.

Add a backend by writing one function with the same signature and registering
it in BACKENDS. Raise SourceError on failure and SourceSkipped when it isn't
configured — never return [] for either. Nothing else in the pipeline changes.
"""

from __future__ import annotations

import base64
import json
import os
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import quote_plus, urlencode

import feedparser

from core.fetch import Fetcher
from core.models import Item


class SourceError(Exception):
    """A source could not be searched: blocked, timed out, 404, bad payload.

    The distinction this exists to protect: "we searched and found nothing" and
    "we could not look" are different answers, and for screening work the
    difference is the whole point. A backend that swallows a 429 and returns []
    renders identically to a clean result, and a clean result that is really a
    failed fetch is a false negative someone signs off on.
    """


class SourceSkipped(Exception):
    """A source was never attempted — not configured, no credentials.

    Deliberately not a SourceError. Nothing is broken and nothing needs
    fixing, but the source still wasn't searched, so it must not be reported
    as a zero either. See CLAUDE.md on degrading without keys.
    """


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _fail(res) -> None:
    """Turn a failed FetchResult into a SourceError carrying the real reason."""
    raise SourceError(res.error or f"HTTP {res.status}")


def _strip_tags(html: str) -> str:
    return re.sub(r"<[^>]+>", " ", html or "").replace("&nbsp;", " ").strip()


# ------------------------------------------------------------------ GDELT

def gdelt(query: str, fetcher: Fetcher, hours: int = 72,
          limit: int = 40) -> list[Item]:
    """Free, no key. Supports sourcecountry:, sourcelang:, domain: operators."""
    url = "https://api.gdeltproject.org/api/v2/doc/doc?" + urlencode({
        "query": query, "mode": "ArtList", "format": "json",
        "timespan": f"{hours}h", "maxrecords": min(limit, 250), "sort": "datedesc",
    })
    res = fetcher.get(url, api=True)
    if not res.ok:
        _fail(res)
    try:
        articles = json.loads(res.html).get("articles", [])
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")

    out = []
    for a in articles:
        if not a.get("url"):
            continue
        out.append(Item(
            url=a["url"], source="gdelt", source_type="news",
            title=(a.get("title") or "").strip(),
            published_at=a.get("seendate", ""),
            lang=a.get("language", ""),
            raw_meta={"domain": a.get("domain", ""),
                      "country": a.get("sourcecountry", "")},
        ))
    return out


# ------------------------------------------------------------ Google News

def google_news(query: str, fetcher: Fetcher, hours: int = 72,
                limit: int = 30) -> list[Item]:
    """Published RSS search endpoint. Broader recall than GDELT on local outlets."""
    when = f"{max(1, hours // 24)}d" if hours >= 24 else f"{hours}h"
    url = (f"https://news.google.com/rss/search?q={quote_plus(query)}"
           f"+when:{when}&hl=en&gl=KE&ceid=KE:en")
    res = fetcher.get(url, api=True)
    if not res.ok:
        _fail(res)

    out = []
    for e in feedparser.parse(res.html).entries[:limit]:
        if not e.get("link"):
            continue
        out.append(Item(
            url=e["link"], source="google_news", source_type="news",
            title=(e.get("title") or "").strip(),
            text=_strip_tags(e.get("summary", ""))[:1000],
            published_at=e.get("published", ""),
            raw_meta={"outlet": (e.get("source", {}) or {}).get("title", "")},
        ))
    return out


# -------------------------------------------------------------- Wikipedia

def wikipedia(query: str, fetcher: Fetcher, hours: int = 0,
              limit: int = 3) -> list[Item]:
    """Background context, not news. Answers 'who or what is this'."""
    url = "https://en.wikipedia.org/w/api.php?" + urlencode({
        "action": "query", "format": "json", "list": "search",
        "srsearch": query, "srlimit": limit,
    })
    res = fetcher.get(url, api=True)
    if not res.ok:
        _fail(res)
    try:
        hits = json.loads(res.html).get("query", {}).get("search", [])
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")

    out = []
    for h in hits:
        title = h.get("title", "")
        out.append(Item(
            url=f"https://en.wikipedia.org/wiki/{quote_plus(title.replace(' ', '_'))}",
            source="wikipedia", source_type="reference",
            title=title,
            text=_strip_tags(h.get("snippet", "")),
            published_at=h.get("timestamp", ""),
        ))
    return out


# ------------------------------------------------------------ Hacker News

def hackernews(query: str, fetcher: Fetcher, hours: int = 72,
               limit: int = 20) -> list[Item]:
    since = int((datetime.now(timezone.utc) - timedelta(hours=hours)).timestamp())
    url = "https://hn.algolia.com/api/v1/search_by_date?" + urlencode({
        "query": query, "hitsPerPage": limit,
        "numericFilters": f"created_at_i>{since}",
    })
    res = fetcher.get(url, api=True)
    if not res.ok:
        _fail(res)
    try:
        hits = json.loads(res.html).get("hits", [])
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")

    out = []
    for h in hits:
        link = h.get("url") or f"https://news.ycombinator.com/item?id={h.get('objectID')}"
        out.append(Item(
            url=link, source="hackernews", source_type="social",
            title=(h.get("title") or h.get("story_title") or "").strip(),
            text=_strip_tags(h.get("comment_text") or h.get("story_text") or "")[:2000],
            author=h.get("author", ""),
            published_at=h.get("created_at", ""),
            raw_meta={"points": h.get("points"), "comments": h.get("num_comments")},
        ))
    return out


# --------------------------------------------------------------- Mastodon

def mastodon(query: str, fetcher: Fetcher, hours: int = 72,
             limit: int = 20, instance: str = "mastodon.social") -> list[Item]:
    """Public post search. Open API, no key. Instances may rate-limit or opt out.

    This is the only genuinely open social network here. Instagram, TikTok,
    LinkedIn and X have no equivalent, which is why they're absent.
    """
    url = (f"https://{instance}/api/v2/search?"
           + urlencode({"q": query, "type": "statuses", "limit": min(limit, 40)}))
    res = fetcher.get(url, api=True)
    if not res.ok:
        _fail(res)
    try:
        statuses = json.loads(res.html).get("statuses", [])
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")

    out = []
    for s in statuses:
        acct = (s.get("account") or {}).get("acct", "")
        out.append(Item(
            url=s.get("url") or s.get("uri", ""), source=f"mastodon:{instance}",
            source_type="social",
            title=_strip_tags(s.get("content", ""))[:120],
            text=_strip_tags(s.get("content", "")),
            author=acct, published_at=s.get("created_at", ""),
            raw_meta={"reblogs": s.get("reblogs_count"),
                      "favourites": s.get("favourites_count")},
        ))
    return [i for i in out if i.url]


# -------------------------------------------------------------- SEC EDGAR

def sec_edgar(query: str, fetcher: Fetcher, hours: int = 0,
              limit: int = 15) -> list[Item]:
    """US filings full-text search. Free. Requires a real UA with contact info,
    which core/fetch.py already sends."""
    url = "https://efts.sec.gov/LATEST/search-index?" + urlencode(
        {"q": f'"{query}"', "forms": "", "hits": limit})
    res = fetcher.get(url, api=True)
    if not res.ok:
        url = "https://efts.sec.gov/LATEST/search-index?" + urlencode({"q": query})
        res = fetcher.get(url, api=True)
        if not res.ok:
            _fail(res)
    try:
        hits = json.loads(res.html).get("hits", {}).get("hits", [])
    except (json.JSONDecodeError, AttributeError):
        raise SourceError("200 but the response body was not the expected JSON")

    out = []
    for h in hits[:limit]:
        src = h.get("_source", {})
        cid = (h.get("_id") or "").split(":")[0].replace("-", "")
        out.append(Item(
            url=f"https://www.sec.gov/Archives/edgar/data/{cid}",
            source="sec_edgar", source_type="regulatory",
            title=" | ".join(filter(None, [src.get("display_names", [""])[0],
                                           src.get("file_type", "")])),
            published_at=src.get("file_date", ""),
            raw_meta={"form": src.get("root_form", "")},
        ))
    return out


# --------------------------------------------------------- OpenSanctions

def opensanctions(query: str, fetcher: Fetcher, hours: int = 0,
                  limit: int = 10) -> list[Item]:
    """Sanctions, PEP and watchlist matching. Needs a free OPENSANCTIONS_API_KEY.

    Without the key this raises SourceSkipped rather than returning [], so the
    sweep still completes but never reports an unsearched sanctions list as a
    clean one. That is the single most dangerous silent zero in the tool.
    """
    key = os.environ.get("OPENSANCTIONS_API_KEY")
    if not key:
        raise SourceSkipped("OPENSANCTIONS_API_KEY is not set")
    url = ("https://api.opensanctions.org/search/default?"
           + urlencode({"q": query, "limit": limit}))
    # Per request, not on the shared client: the fan-out is concurrent, so
    # assigning to fetcher.client.headers would put this key on whatever other
    # backend happened to be mid-flight.
    res = fetcher.get(url, api=True, headers={"Authorization": f"ApiKey {key}"})
    if not res.ok:
        _fail(res)
    try:
        results = json.loads(res.html).get("results", [])
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")

    out = []
    for r in results:
        props = r.get("properties", {})
        topics = props.get("topics", [])
        out.append(Item(
            url=f"https://www.opensanctions.org/entities/{r.get('id', '')}/",
            source="opensanctions", source_type="watchlist",
            title=f"{r.get('caption', '')} ({r.get('schema', '')})",
            text=("Listed on: " + ", ".join(r.get("datasets", []))
                  + ". Topics: " + ", ".join(topics)
                  + ". Countries: " + ", ".join(props.get("country", []))),
            published_at=r.get("last_seen", ""),
            # A watchlist hit is never noise. Pre-scored so it can't be buried.
            relevance=95, enriched=True,
            raw_meta={"datasets": r.get("datasets", []), "topics": topics},
        ))
    return out


# ------------------------------------------------------------- web search

def web_search(query: str, fetcher: Fetcher, hours: int = 72,
               limit: int = 20) -> list[Item]:
    """The whole indexed web, via Brave's Search API.

    Every other backend here searches one silo. This one is what lets a sweep
    reach an arbitrary domain — a regulator's own site, a *.vercel.app app, a
    company blog — without writing a backend per host. Free tier is 2,000
    queries/month. Needs BRAVE_API_KEY.
    """
    key = os.environ.get("BRAVE_API_KEY")
    if not key:
        raise SourceSkipped("BRAVE_API_KEY is not set")
    freshness = {24: "pd", 168: "pw", 720: "pm"}.get(hours, "" if hours > 720 else "pw")
    params = {"q": query, "count": min(limit, 20)}
    if freshness:
        params["freshness"] = freshness
    url = "https://api.search.brave.com/res/v1/web/search?" + urlencode(params)
    res = fetcher.get(url, api=True, headers={
        "X-Subscription-Token": key, "Accept": "application/json"})
    if not res.ok:
        _fail(res)
    try:
        hits = json.loads(res.html).get("web", {}).get("results", [])
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")

    out = []
    for h in hits[:limit]:
        if not h.get("url"):
            continue
        out.append(Item(
            url=h["url"], source="web_search", source_type="news",
            title=_strip_tags(h.get("title", "")),
            text=_strip_tags(h.get("description", "")),
            published_at=h.get("page_age", "") or h.get("age", ""),
            raw_meta={"domain": (h.get("meta_url", {}) or {}).get("hostname", "")},
        ))
    return out


# ------------------------------------------------------------------ GLEIF

def gleif(query: str, fetcher: Fetcher, hours: int = 0,
          limit: int = 10) -> list[Item]:
    """Legal Entity Identifiers. Free, no registration, no key.

    Answers "is this the same company?" — the name collision that produces the
    classic adverse-media false positive. An LEI is an unambiguous handle where
    a name is not.
    """
    url = "https://api.gleif.org/api/v1/lei-records?" + urlencode({
        "filter[fulltext]": query, "page[size]": min(limit, 50)})
    res = fetcher.get(url, api=True, headers={"Accept": "application/vnd.api+json"})
    if not res.ok:
        _fail(res)
    try:
        records = json.loads(res.html).get("data", [])
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")

    out = []
    for r in records[:limit]:
        a = r.get("attributes", {}) or {}
        ent = a.get("entity", {}) or {}
        name = (ent.get("legalName", {}) or {}).get("name", "")
        addr = ent.get("legalAddress", {}) or {}
        country = addr.get("country", "")
        status = ent.get("status", "")
        lei = a.get("lei", r.get("id", ""))
        if not lei:
            continue
        out.append(Item(
            url=f"https://search.gleif.org/#/record/{lei}",
            source="gleif", source_type="dataset",
            title=f"{name} ({country})" if country else name,
            text=(f"LEI {lei}. Legal name: {name}. Country: {country}. "
                  f"Entity status: {status}. "
                  f"Registered: {', '.join(filter(None, addr.get('addressLines', []) or []))}"),
            published_at=(a.get("registration", {}) or {}).get("lastUpdateDate", ""),
            raw_meta={"lei": lei, "country": country, "status": status},
        ))
    return out


# ---------------------------------------------------------- OpenCorporates

def opencorporates(query: str, fetcher: Fetcher, hours: int = 0,
                   limit: int = 15) -> list[Item]:
    """Company registry data across 140+ jurisdictions. Needs
    OPENCORPORATES_API_KEY (free tier available on request)."""
    key = os.environ.get("OPENCORPORATES_API_KEY")
    if not key:
        raise SourceSkipped("OPENCORPORATES_API_KEY is not set")
    url = "https://api.opencorporates.com/v0.4/companies/search?" + urlencode(
        {"q": query, "per_page": min(limit, 30), "api_token": key})
    res = fetcher.get(url, api=True)
    if not res.ok:
        _fail(res)
    try:
        companies = (json.loads(res.html).get("results", {}) or {}).get("companies", [])
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")

    out = []
    for entry in companies[:limit]:
        c = entry.get("company", {}) or {}
        if not c.get("opencorporates_url"):
            continue
        out.append(Item(
            url=c["opencorporates_url"], source="opencorporates",
            source_type="dataset",
            title=f"{c.get('name', '')} ({c.get('jurisdiction_code', '')})",
            text=(f"Company number {c.get('company_number', '')}. "
                  f"Status: {c.get('current_status', 'unknown')}. "
                  f"Incorporated: {c.get('incorporation_date', 'unknown')}. "
                  f"Type: {c.get('company_type', '')}"),
            published_at=c.get("updated_at", ""),
            raw_meta={"jurisdiction": c.get("jurisdiction_code", ""),
                      "status": c.get("current_status", "")},
        ))
    return out


# ---------------------------------------------------------------- Bluesky

def bluesky(query: str, fetcher: Fetcher, hours: int = 72,
            limit: int = 25) -> list[Item]:
    """Post search over the AT Protocol. Needs BLUESKY_HANDLE and
    BLUESKY_APP_PASSWORD (Settings -> App Passwords; free, revocable, and not
    your account password).

    Read endpoints like getProfile are open, but searchPosts is refused at the
    CDN without a session — diagnose.py caught this returning 403 for every
    user agent, which as a silent [] would have looked like "no posts found"
    forever. App passwords are Bluesky's supported mechanism for exactly this,
    so this stays an intended-consumer API call, not a scrape.
    """
    handle = os.environ.get("BLUESKY_HANDLE")
    app_password = os.environ.get("BLUESKY_APP_PASSWORD")
    if not (handle and app_password):
        raise SourceSkipped("BLUESKY_HANDLE / BLUESKY_APP_PASSWORD are not set")

    auth = fetcher.post(
        "https://bsky.social/xrpc/com.atproto.server.createSession",
        json_body={"identifier": handle, "password": app_password}, api=True)
    if not auth.ok:
        _fail(auth)
    try:
        jwt = json.loads(auth.html).get("accessJwt")
    except json.JSONDecodeError:
        raise SourceError("auth response was not valid JSON")
    if not jwt:
        raise SourceError("no session token returned — check handle/app password")

    url = "https://api.bsky.app/xrpc/app.bsky.feed.searchPosts?" + urlencode(
        {"q": query, "limit": min(limit, 100), "sort": "latest"})
    res = fetcher.get(url, api=True, headers={"Authorization": f"Bearer {jwt}"})
    if not res.ok:
        _fail(res)
    try:
        posts = json.loads(res.html).get("posts", [])
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")

    out = []
    for p in posts[:limit]:
        rec = p.get("record", {}) or {}
        handle = (p.get("author", {}) or {}).get("handle", "")
        rkey = (p.get("uri", "") or "").rsplit("/", 1)[-1]
        if not (handle and rkey):
            continue
        text = rec.get("text", "")
        out.append(Item(
            url=f"https://bsky.app/profile/{handle}/post/{rkey}",
            source="bluesky", source_type="social",
            title=text[:120], text=text, author=handle,
            published_at=rec.get("createdAt", ""),
            raw_meta={"likes": p.get("likeCount"), "reposts": p.get("repostCount")},
        ))
    return out


# ----------------------------------------------------------------- Reddit

def reddit(query: str, fetcher: Fetcher, hours: int = 72,
           limit: int = 25) -> list[Item]:
    """Official OAuth API. Needs REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET
    (free: create a 'script' app at reddit.com/prefs/apps).

    Reddit requires OAuth for automated access; the old unauthenticated .json
    endpoints are not a supported interface and are being closed off, so this
    deliberately does not fall back to them.
    """
    cid = os.environ.get("REDDIT_CLIENT_ID")
    secret = os.environ.get("REDDIT_CLIENT_SECRET")
    if not (cid and secret):
        raise SourceSkipped("REDDIT_CLIENT_ID / REDDIT_CLIENT_SECRET are not set")

    basic = base64.b64encode(f"{cid}:{secret}".encode()).decode()
    token_res = fetcher.post(
        "https://www.reddit.com/api/v1/access_token",
        data={"grant_type": "client_credentials"},
        headers={"Authorization": f"Basic {basic}"}, api=True)
    if not token_res.ok:
        _fail(token_res)
    try:
        token = json.loads(token_res.html).get("access_token")
    except json.JSONDecodeError:
        raise SourceError("auth response was not valid JSON")
    if not token:
        raise SourceError("no access token returned — check the credentials")

    window = "day" if hours <= 24 else "week" if hours <= 168 else "month"
    url = "https://oauth.reddit.com/search?" + urlencode(
        {"q": query, "limit": min(limit, 100), "sort": "new", "t": window,
         "type": "link"})
    res = fetcher.get(url, api=True, headers={"Authorization": f"Bearer {token}"})
    if not res.ok:
        _fail(res)
    try:
        children = (json.loads(res.html).get("data", {}) or {}).get("children", [])
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")

    out = []
    for child in children[:limit]:
        d = child.get("data", {}) or {}
        if not d.get("permalink"):
            continue
        created = d.get("created_utc")
        out.append(Item(
            url=f"https://www.reddit.com{d['permalink']}",
            source="reddit", source_type="social",
            title=(d.get("title") or "").strip(),
            text=_strip_tags(d.get("selftext", ""))[:2000],
            author=d.get("author", ""),
            published_at=(_iso(datetime.fromtimestamp(created, timezone.utc))
                          if created else ""),
            raw_meta={"subreddit": d.get("subreddit", ""),
                      "score": d.get("score"), "comments": d.get("num_comments")},
        ))
    return out


# ---------------------------------------------------------------------- X

def x_twitter(query: str, fetcher: Fetcher, hours: int = 72,
              limit: int = 20) -> list[Item]:
    """X/Twitter recent search via the official paid API. Needs X_BEARER_TOKEN.

    This is the official documented endpoint on a paid tier, which is why it is
    here when scraping X is not: it's a supported interface with a real
    contract behind it, so it fails loudly rather than silently. Recent search
    only reaches back 7 days on most tiers — beyond that this returns nothing,
    which is a real limit of the product, not of the sweep.
    """
    token = os.environ.get("X_BEARER_TOKEN")
    if not token:
        raise SourceSkipped("X_BEARER_TOKEN is not set")
    url = "https://api.x.com/2/tweets/search/recent?" + urlencode({
        "query": f"{query} -is:retweet",
        "max_results": max(10, min(limit, 100)),
        "tweet.fields": "created_at,public_metrics,lang,author_id",
        "expansions": "author_id",
        "user.fields": "username",
    })
    res = fetcher.get(url, api=True, headers={"Authorization": f"Bearer {token}"})
    if not res.ok:
        _fail(res)
    try:
        payload = json.loads(res.html)
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")

    users = {u["id"]: u.get("username", "")
             for u in (payload.get("includes", {}) or {}).get("users", [])}
    out = []
    for t in payload.get("data", [])[:limit]:
        handle = users.get(t.get("author_id", ""), "i")
        text = t.get("text", "")
        out.append(Item(
            url=f"https://x.com/{handle}/status/{t.get('id', '')}",
            source="x", source_type="social",
            title=text[:120], text=text, author=handle,
            published_at=t.get("created_at", ""), lang=t.get("lang", ""),
            raw_meta=t.get("public_metrics", {}) or {},
        ))
    return out


BACKENDS = {
    "gdelt": gdelt,
    "google_news": google_news,
    "web_search": web_search,
    "wikipedia": wikipedia,
    "hackernews": hackernews,
    "mastodon": mastodon,
    "bluesky": bluesky,
    "reddit": reddit,
    "x": x_twitter,
    "gleif": gleif,
    "opencorporates": opencorporates,
    "sec_edgar": sec_edgar,
    "opensanctions": opensanctions,
}

# Which backends need credentials, and the variable each one wants. One map,
# because there are three consumers — `run.py sources`, /api/sources for the
# chip gating, and diagnose.py — and when this lived in two of them the CLI
# went on claiming opensanctions was the only key-gated source long after five
# more had been added.
BACKEND_KEYS = {
    "opensanctions": "OPENSANCTIONS_API_KEY",
    "web_search": "BRAVE_API_KEY",
    "opencorporates": "OPENCORPORATES_API_KEY",
    "x": "X_BEARER_TOKEN",
    "reddit": "REDDIT_CLIENT_ID",
    "bluesky": "BLUESKY_APP_PASSWORD",
}


def has_credentials(name: str) -> bool:
    """True when this backend either needs no key or has the one it needs."""
    var = BACKEND_KEYS.get(name)
    return not var or bool(os.environ.get(var))


# Key-gated backends stay in the defaults: they now disable themselves in the
# UI when the key is absent, and raise SourceSkipped rather than a silent zero
# on the CLI, so including them costs nothing and forgetting a key is visible.
DEFAULT_BACKENDS = ["gdelt", "google_news", "web_search", "wikipedia",
                    "hackernews", "mastodon", "bluesky", "reddit", "x",
                    "gleif", "opencorporates", "opensanctions"]
