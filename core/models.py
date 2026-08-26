"""The one record shape every adapter must produce.

If a new source can be mapped onto Item, it plugs into the pipeline for free.
If it can't, the source is telling you it needs its own storage.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Item:
    # --- identity ---
    url: str
    source: str                     # adapter name, e.g. "rss:businessdaily"
    source_type: str                # news | regulatory | social | dataset

    # --- content ---
    title: str = ""
    text: str = ""                  # cleaned body, no nav/ads
    author: str = ""
    published_at: str = ""          # ISO8601 if the source gives us one

    # --- pipeline metadata ---
    fetched_at: str = field(default_factory=_now)
    lang: str = ""
    raw_meta: dict[str, Any] = field(default_factory=dict)

    # --- filled in by enrich.py, all optional ---
    summary: str = ""
    entities: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    relevance: int = 0              # 0-100, model-assigned
    enriched: bool = False

    @property
    def content_hash(self) -> str:
        """Dedupe key. Deliberately ignores URL: the same story syndicated to
        five outlets under five URLs is one story, and you only want to read it
        once. Falls back to URL when there's no body text yet."""
        basis = (self.title.strip().lower() + "|" + self.text.strip()[:2000].lower())
        if not basis.strip("|"):
            basis = self.url
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()

    def to_row(self) -> dict[str, Any]:
        d = asdict(self)
        d["entities"] = "\n".join(self.entities)
        d["categories"] = "\n".join(self.categories)
        d["raw_meta"] = str(self.raw_meta)
        d["content_hash"] = self.content_hash
        d["enriched"] = int(self.enriched)
        return d
