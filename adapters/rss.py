"""RSS and Atom feeds — the cheapest source that exists, so start here.

Point this at a publisher's own feed and you get titles, links and dates with
no scraping and no key. Point it at a self-hosted RSSHub instance and a lot of
feed-less sites become feeds too.

The body is a second request per entry, so it is gated twice: `fetch_body` in
config, and `store.is_seen()` — a feed re-serves its whole window on every
poll, and re-downloading thirty articles every fifteen minutes to discover
nothing changed is how you get blocked.
"""

from __future__ import annotations

from datetime import datetime, timezone

import feedparser

from core.clean import extract
from core.fetch import Fetcher
from core.models import Item
from core.store import Store

# feedparser hands back a time.struct_time when it can parse the date at all.
_DATE_FIELDS = ("published_parsed", "updated_parsed")


def _published(entry) -> str:
    for field in _DATE_FIELDS:
        parsed = entry.get(field)
        if parsed:
            try:
                return datetime(*parsed[:6], tzinfo=timezone.utc).isoformat()
            except (TypeError, ValueError):
                pass
    # Better an empty string than today's date: a missing timestamp must not
    # silently become "just published" and jump the ranking.
    return (entry.get("published") or entry.get("updated") or "").strip()


def _summary(entry) -> str:
    """The feed's own description, stripped of markup, as a body fallback."""
    raw = entry.get("summary", "") or ""
    if not raw:
        content = entry.get("content") or []
        raw = content[0].get("value", "") if content else ""
    if not raw:
        return ""
    text = extract(f"<html><body>{raw}</body></html>")["text"]
    return text or ""


def collect(url: str, name: str, source_type: str, fetcher: Fetcher,
            store: Store, fetch_body: bool = True, limit: int = 25,
            errors: list[str] | None = None) -> list[Item]:
    """Read one feed. Returns only entries this store has not seen before."""
    errors = errors if errors is not None else []
    source = f"rss:{name}"

    res = fetcher.get(url, api=True)
    if not res.ok:
        errors.append(f"{source}: {res.error or f'HTTP {res.status}'}")
        return []

    feed = feedparser.parse(res.html)
    # bozo means the XML was malformed. feedparser still recovers entries from
    # most broken feeds, so this is worth a note rather than an abort.
    if feed.bozo and not feed.entries:
        errors.append(f"{source}: unparseable feed ({feed.bozo_exception})")
        return []

    out: list[Item] = []
    for entry in feed.entries[:limit]:
        link = (entry.get("link") or "").strip()
        if not link or store.is_seen(link):
            continue

        item = Item(
            url=link,
            source=source,
            source_type=source_type,
            title=(entry.get("title") or "").strip(),
            author=(entry.get("author") or "").strip(),
            published_at=_published(entry),
            text=_summary(entry),
            raw_meta={"feed": url, "feed_title": feed.feed.get("title", "")},
        )

        if fetch_body:
            # Crawling a publisher's article page, not calling an API, so this
            # one obeys robots.txt — api=False is the default and correct here.
            body = fetcher.get(link)
            if body.ok:
                data = extract(body.html, link)
                if data["text"]:
                    item.text = data["text"]
                item.title = item.title or data["title"]
                item.author = item.author or data["author"]
                item.published_at = item.published_at or data["published_at"]
                item.lang = data["lang"]
            else:
                # Keep the item: the feed entry alone is still a signal, and
                # dropping it would make a blocked body look like no story.
                item.raw_meta["fetch_error"] = body.error or f"HTTP {body.status}"

        out.append(item)
    return out
