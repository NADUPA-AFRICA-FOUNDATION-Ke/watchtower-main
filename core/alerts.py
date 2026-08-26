"""Alerting. Two independent triggers, because they fail differently.

  Keyword rules   - deterministic, auditable, catch known names exactly.
                    Miss anything phrased unexpectedly.
  Model relevance - catches the unexpected phrasing.
                    Occasionally confident and wrong.

Run both. Anything hit by either goes in the digest, tagged with which fired.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path


def keyword_hits(row: sqlite3.Row, watchlist: list[str]) -> list[str]:
    """Whole-word, case-insensitive. Whole-word matters: 'Sanctions' shouldn't
    fire on 'sanctioned' contexts you don't care about, and short terms like
    'CBK' shouldn't fire inside other words."""
    haystack = f"{row['title']} {row['text']}".lower()
    hits = []
    for term in watchlist:
        pattern = r"\b" + re.escape(term.lower()) + r"\b"
        if re.search(pattern, haystack):
            hits.append(term)
    return hits


def select(store, watchlist: list[str], min_relevance: int = 60) -> list[dict]:
    """Everything unalerted that trips either trigger."""
    selected = []
    for row in store.pending_alerts(min_relevance=0):
        hits = keyword_hits(row, watchlist)
        by_model = row["relevance"] >= min_relevance
        if not (hits or by_model):
            continue
        selected.append({
            "content_hash": row["content_hash"],
            "title": row["title"],
            "url": row["url"],
            "source": row["source"],
            "source_type": row["source_type"],
            "summary": row["summary"],
            "text": row["text"],
            "relevance": row["relevance"],
            "keyword_hits": hits,
            "triggered_by": ("keyword+model" if hits and by_model
                             else "keyword" if hits else "model"),
        })
    selected.sort(key=lambda x: (-x["relevance"], x["title"]))
    return selected


def render(selected: list[dict], brief: str = "") -> str:
    if not selected:
        return "No new items matched the watchlist.\n"

    out = [f"{len(selected)} new item(s) matched.\n"]
    if brief:
        out.append(brief.strip() + "\n")
        out.append("-" * 60 + "\n")

    for item in selected:
        flags = f"[{item['relevance']:>3}] [{item['triggered_by']}]"
        out.append(f"{flags} {item['title'] or '(untitled)'}")
        out.append(f"      {item['source']}  |  {item['url']}")
        if item["keyword_hits"]:
            out.append(f"      matched: {', '.join(item['keyword_hits'])}")
        body = item["summary"] or item["text"][:220].replace("\n", " ")
        if body:
            out.append(f"      {body}")
        out.append("")
    return "\n".join(out)


def write(text: str, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p
