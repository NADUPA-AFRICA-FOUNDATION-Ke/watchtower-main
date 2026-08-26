"""Reddit for scheduled mode, and the retention rule that governs all of it.

Social posts are personal data. Kenya's Data Protection Act 2019 requires a
lawful basis, a stated purpose and a retention limit, and a retention limit you
do not enforce is not a retention limit. `purge_expired` runs on every
scheduled collect — `run.py::cmd_collect` calls it unconditionally, not only
when Reddit is configured, because posts collected last month still age out
when you stop collecting new ones. Do not remove that call.

Reddit is here because it publishes an OAuth API with a contract behind it.
Instagram, TikTok, LinkedIn and Facebook are absent on purpose: they prohibit
scraping and they fail *silently*, which is the worst failure mode for
monitoring — you believe you have coverage and you do not. See CLAUDE.md.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import httpx

from core.models import Item
from core.store import Store

# How long a collected post may be kept. Enforced on every scheduled run.
RETENTION_DAYS = int(os.environ.get("WATCHTOWER_RETENTION_DAYS", "90"))

TOKEN_URL = "https://www.reddit.com/api/v1/access_token"
API = "https://oauth.reddit.com"


def _token(client_id: str, secret: str, user_agent: str) -> str:
    r = httpx.post(
        TOKEN_URL,
        data={"grant_type": "client_credentials"},
        auth=(client_id, secret),
        headers={"User-Agent": user_agent},
        timeout=20.0,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def collect_reddit(subreddits: list[str], store: Store, limit: int = 20,
                   user_agent: str = "watchtower/0.1 (monitoring research)",
                   errors: list[str] | None = None) -> list[Item]:
    """New posts from each subreddit. Returns [] with a recorded reason if the
    credentials are absent — a scheduled run must not die on one dead source."""
    errors = errors if errors is not None else []
    client_id = os.environ.get("REDDIT_CLIENT_ID")
    secret = os.environ.get("REDDIT_CLIENT_SECRET")
    if not (client_id and secret):
        errors.append("reddit: REDDIT_CLIENT_ID / REDDIT_CLIENT_SECRET are not set")
        return []

    try:
        token = _token(client_id, secret, user_agent)
    except Exception as e:
        errors.append(f"reddit: auth failed ({type(e).__name__}: {e})")
        return []

    headers = {"Authorization": f"bearer {token}", "User-Agent": user_agent}
    out: list[Item] = []

    with httpx.Client(headers=headers, timeout=20.0) as client:
        for sub in subreddits:
            sub = sub.strip().lstrip("r/")
            if not sub:
                continue
            try:
                r = client.get(f"{API}/r/{sub}/new",
                               params={"limit": min(limit, 100)})
                if r.status_code != 200:
                    errors.append(f"reddit:{sub}: HTTP {r.status_code}")
                    continue
                children = r.json().get("data", {}).get("children", [])
            except Exception as e:
                errors.append(f"reddit:{sub}: {type(e).__name__}: {e}")
                continue

            for child in children:
                d = child.get("data", {})
                permalink = d.get("permalink")
                if not permalink:
                    continue
                url = f"https://www.reddit.com{permalink}"
                if store.is_seen(url):
                    continue
                created = d.get("created_utc")
                out.append(Item(
                    url=url,
                    source=f"reddit:{sub}",
                    source_type="social",
                    title=(d.get("title") or "").strip(),
                    text=(d.get("selftext") or "").strip(),
                    author=(d.get("author") or "").strip(),
                    published_at=(datetime.fromtimestamp(created, timezone.utc)
                                  .isoformat() if created else ""),
                    raw_meta={"subreddit": sub, "score": d.get("score", 0),
                              "num_comments": d.get("num_comments", 0),
                              "link": d.get("url", ""),
                              # Stamped at collection so purge_expired does not
                              # depend on the post's own date, which a source
                              # can omit or backdate.
                              "collected_at": datetime.now(timezone.utc).isoformat()},
                ))
    return out


def purge_expired(store: Store, retention_days: int = RETENTION_DAYS) -> int:
    """Delete social items older than the retention limit. Returns the count.

    Keyed on `fetched_at`, which watchtower sets itself, rather than on the
    post's `published_at` — a source that omits or backdates its timestamp must
    not be able to extend how long we hold someone's post.
    """
    cutoff = (datetime.now(timezone.utc)
              - timedelta(days=retention_days)).isoformat()
    cur = store.conn.execute(
        "DELETE FROM items WHERE source_type = 'social' AND fetched_at < ?",
        (cutoff,))
    store.conn.commit()
    return cur.rowcount or 0
