#!/usr/bin/env python3
"""Why did every source return zero?

Drop this in the repo root and run it. It hits each backend's real endpoint and
reports the actual reason for failure, which the sweep currently swallows.

    python diagnose.py
    python diagnose.py --query "beneficial ownership Kenya"

Reads nothing, writes nothing, changes nothing. Safe to run against production.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.robotparser
from pathlib import Path
from urllib.parse import quote_plus, urlencode, urlparse

sys.path.insert(0, str(Path(__file__).parent))

import httpx
import yaml

# Each entry: (name, url_builder, what a healthy response looks like)
ENDPOINTS = {
    "gdelt": lambda q: "https://api.gdeltproject.org/api/v2/doc/doc?" + urlencode(
        {"query": q, "mode": "ArtList", "format": "json",
         "timespan": "72h", "maxrecords": 5, "sort": "datedesc"}),
    "google_news": lambda q: (
        f"https://news.google.com/rss/search?q={quote_plus(q)}"
        "+when:3d&hl=en&gl=KE&ceid=KE:en"),
    "wikipedia": lambda q: "https://en.wikipedia.org/w/api.php?" + urlencode(
        {"action": "query", "format": "json", "list": "search",
         "srsearch": q, "srlimit": 3}),
    "hackernews": lambda q: "https://hn.algolia.com/api/v1/search?" + urlencode(
        {"query": q, "hitsPerPage": 5}),
    "mastodon": lambda q: "https://mastodon.social/api/v2/search?" + urlencode(
        {"q": q, "type": "statuses", "limit": 5}),
    "sec_edgar": lambda q: "https://efts.sec.gov/LATEST/search-index?" + urlencode(
        {"q": f'"{q}"', "hits": 5}),
    "opensanctions": lambda q: "https://api.opensanctions.org/search/default?"
                               + urlencode({"q": q, "limit": 5}),
    "bluesky": lambda q: "https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts?"
                         + urlencode({"q": q, "limit": 5}),
    "gleif": lambda q: "https://api.gleif.org/api/v1/lei-records?"
                       + urlencode({"filter[fulltext]": q, "page[size]": 5}),
    "web_search": lambda q: "https://api.search.brave.com/res/v1/web/search?"
                            + urlencode({"q": q, "count": 5}),
    "opencorporates": lambda q: "https://api.opencorporates.com/v0.4/companies/search?"
                                + urlencode({"q": q, "per_page": 5}),
    "reddit": lambda q: "https://oauth.reddit.com/search?" + urlencode(
        {"q": q, "limit": 5}),
    "x": lambda q: "https://api.x.com/2/tweets/search/recent?" + urlencode(
        {"query": q, "max_results": 10}),
}

# Endpoints that answer 401/403 without credentials. diagnose.py deliberately
# sends none — the point is to prove the endpoint is reachable and identify why
# it refuses, not to exercise the key.
NEEDS_KEY = {"opensanctions": "OPENSANCTIONS_API_KEY",
             "web_search": "BRAVE_API_KEY",
             "opencorporates": "OPENCORPORATES_API_KEY",
             "reddit": "REDDIT_CLIENT_ID / REDDIT_CLIENT_SECRET",
             "x": "X_BEARER_TOKEN",
             "bluesky": "BLUESKY_HANDLE / BLUESKY_APP_PASSWORD"}


def load_ua() -> str:
    try:
        cfg = yaml.safe_load(Path("config.yaml").read_text(encoding="utf-8"))
        return cfg["fetch"]["user_agent"]
    except Exception:
        return "watchtower-diagnose/0.1"


def robots_verdict(client: httpx.Client, url: str, ua: str) -> str:
    """What robots.txt says about this exact URL, and why."""
    p = urlparse(url)
    try:
        r = client.get(f"{p.scheme}://{p.netloc}/robots.txt", timeout=10.0)
    except Exception as e:
        return f"unreachable ({type(e).__name__}) -> treated as ALLOWED"
    if r.status_code != 200:
        return f"HTTP {r.status_code} -> treated as ALLOWED"

    rp = urllib.robotparser.RobotFileParser()
    rp.parse(r.text.splitlines())
    allowed = rp.can_fetch(ua, url)
    if allowed:
        return "ALLOWED"

    # Find the rule that did it, so the answer is actionable.
    path = p.path or "/"
    culprits = [ln.strip() for ln in r.text.splitlines()
                if ln.strip().lower().startswith("disallow:")
                and (rule := ln.split(":", 1)[1].strip())
                and rule != "/" and path.startswith(rule)]
    why = f" (matched: {culprits[0]})" if culprits else ""
    return f"BLOCKED{why}"


def probe(name: str, url: str, client: httpx.Client, ua: str) -> dict:
    out = {"name": name, "url": url}
    out["robots"] = robots_verdict(client, url, ua)

    t0 = time.monotonic()
    try:
        r = client.get(url, timeout=60.0)
        out["ms"] = int((time.monotonic() - t0) * 1000)
        out["status"] = r.status_code
        body = r.text
        out["bytes"] = len(body)

        if r.status_code in (401, 403, 422) and name in NEEDS_KEY:
            out["result"] = f"HTTP {r.status_code} — reachable, needs credentials"
            out["hint"] = f"set {NEEDS_KEY[name]}"
            return out

        if r.status_code != 200:
            out["result"] = f"HTTP {r.status_code}"
            out["hint"] = {
                403: "blocked — usually user agent or missing contact info",
                404: "endpoint moved or the path is wrong",
                429: "rate limited — slow down",
            }.get(r.status_code, body[:120].replace("\n", " "))
            return out

        ctype = r.headers.get("content-type", "")
        if "json" in ctype or body.lstrip().startswith(("{", "[")):
            data = json.loads(body)
            count = None
            for key in ("articles", "hits", "results", "statuses",
                        "posts", "data"):
                if isinstance(data, dict) and key in data:
                    count = len(data[key])
                    break
            if count is None and isinstance(data, dict):
                q = data.get("query", {})
                if isinstance(q, dict) and "search" in q:
                    count = len(q["search"])
            out["result"] = (f"OK, {count} record(s)" if count is not None
                             else "OK, JSON but unrecognised shape")
        elif "<rss" in body[:600] or "<feed" in body[:600]:
            out["result"] = f"OK, feed with {body.count('<item')} item(s)"
        else:
            out["result"] = f"200 but not JSON or feed (content-type: {ctype})"
            out["hint"] = body[:120].replace("\n", " ")
    except json.JSONDecodeError:
        out["result"] = "200 but body is not valid JSON"
        out["hint"] = body[:120].replace("\n", " ")
    except Exception as e:
        out["ms"] = int((time.monotonic() - t0) * 1000)
        out["result"] = f"{type(e).__name__}: {e}"
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--query", default="beneficial ownership Kenya")
    args = ap.parse_args()

    ua = load_ua()
    print(f"\nuser agent: {ua}")
    print(f"query:      {args.query}\n")
    print(f"  {'source':<14} {'robots':<34} {'ms':>6}  result")
    print("  " + "-" * 88)

    client = httpx.Client(headers={"User-Agent": ua}, follow_redirects=True)
    rows = []
    for name, build in ENDPOINTS.items():
        row = probe(name, build(args.query), client, ua)
        rows.append(row)
        print(f"  {name:<14} {row['robots']:<34} {row.get('ms', 0):>6}  "
              f"{row['result']}")
        if row.get("hint"):
            print(f"  {'':<14} {'':<34} {'':>6}  -> {row['hint']}")
    client.close()

    blocked = [r for r in rows if r["robots"].startswith("BLOCKED")]
    working = [r for r in rows if r["result"].startswith("OK")]

    print()
    if blocked:
        print(f"  {len(blocked)} endpoint(s) blocked by robots.txt: "
              f"{', '.join(r['name'] for r in blocked)}")
        print("  These are documented public APIs, not pages to crawl. robots.txt")
        print("  governs indexing, not API consumption — the sweep should not be")
        print("  applying it to declared API endpoints. See prompts/02-fix-recall.md")
    print(f"  {len(working)}/{len(rows)} endpoint(s) returning usable data.")
    print()
    return 0 if working else 1


if __name__ == "__main__":
    sys.exit(main())
