"""GDELT for scheduled mode: standing queries rather than one-off searches.

The sweep backend in `core/sources.py` takes `hours`; this takes GDELT's own
`timespan` string, because a schedule is written in the units the schedule runs
on ("24h" for a daily job) and translating through hours loses nothing but
gains an off-by-one every time someone edits the cron.

GDELT rate-limits hard from a single IP and states a five-second minimum in its
own 429 body. `core/fetch.py` honours that floor, so the retry here is the
fetcher's, not a second one layered on top.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlencode

from core.clean import extract
from core.fetch import Fetcher
from core.models import Item
from core.store import Store

API = "https://api.gdeltproject.org/api/v2/doc/doc"

# GDELT returns "20260813T104500Z", which is ISO-ish but not ISO. Everything
# downstream sorts these as strings, so normalise rather than store two shapes.
_SEENDATE = re.compile(r"^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z?$")


def _iso(seendate: str) -> str:
    m = _SEENDATE.match((seendate or "").strip())
    if not m:
        return (seendate or "").strip()
    y, mo, d, h, mi, s = m.groups()
    return f"{y}-{mo}-{d}T{h}:{mi}:{s}+00:00"


def collect(query: str, fetcher: Fetcher, store: Store, timespan: str = "24h",
            max_records: int = 50, fetch_body: bool = False,
            errors: list[str] | None = None) -> list[Item]:
    """Run one standing GDELT query. Returns only articles not already seen."""
    errors = errors if errors is not None else []
    url = API + "?" + urlencode({
        "query": query, "mode": "ArtList", "format": "json",
        "timespan": timespan, "maxrecords": min(max_records, 250),
        "sort": "datedesc",
    })

    res = fetcher.get(url, api=True)
    if not res.ok:
        errors.append(f"gdelt: {res.error or f'HTTP {res.status}'}")
        return []
    try:
        articles = json.loads(res.html).get("articles", [])
    except json.JSONDecodeError:
        # GDELT answers 200 with an HTML error page when a query is malformed.
        errors.append("gdelt: 200 but the body was not JSON (check the query syntax)")
        return []

    out: list[Item] = []
    for a in articles:
        link = (a.get("url") or "").strip()
        if not link or store.is_seen(link):
            continue

        item = Item(
            url=link,
            source="gdelt",
            source_type="news",
            title=(a.get("title") or "").strip(),
            published_at=_iso(a.get("seendate", "")),
            lang=a.get("language", ""),
            raw_meta={"domain": a.get("domain", ""),
                      "country": a.get("sourcecountry", ""),
                      "query": query},
        )

        # Off by default: GDELT indexes thousands of outlets and most standing
        # queries want headline-level breadth, not a body fetch per hit.
        if fetch_body:
            body = fetcher.get(link)
            if body.ok:
                data = extract(body.html, link)
                item.text = data["text"]
                item.title = item.title or data["title"]
                item.author = data["author"]
                item.lang = item.lang or data["lang"]
            else:
                item.raw_meta["fetch_error"] = body.error or f"HTTP {body.status}"

        out.append(item)
    return out
