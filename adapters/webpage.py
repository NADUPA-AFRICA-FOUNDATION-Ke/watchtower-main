"""Listing pages that publish no feed — most regulators, in practice.

This is a link differ, not a scraper. It reads every anchor on the page, keeps
the ones matching `link_pattern`, and treats anything `store.is_seen()` has not
recorded as new. That is the whole design, and it is why it survives a site
redesign: there is no CSS selector to break. A regulator can rebuild their
press-release page from scratch and this keeps working as long as the circulars
are still links.

Regulator circulars are usually PDFs, so PDFs are read rather than merely
recorded. `pypdf` is an optional dependency — without it the link is still
captured, with a note saying why the body is empty, because a PDF nobody read
must not look like a page with nothing in it.
"""

from __future__ import annotations

import io
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from core.clean import extract
from core.fetch import Fetcher
from core.models import Item
from core.store import Store

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None

# How much of a circular to keep. enrich.py truncates again before the model
# sees it; this just stops a 400-page annual report entering the database.
MAX_PDF_CHARS = 40000
MAX_PDF_PAGES = 40


class _Links(HTMLParser):
    """Every href on the page, with its anchor text."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._href = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self._href, self._text = href, []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, " ".join(self._text).strip()))
            self._href, self._text = None, []


def _pdf_text(payload: bytes) -> tuple[str, str]:
    """Return (text, note). The note explains an empty result rather than hiding it."""
    if PdfReader is None:
        return "", "pypdf is not installed — PDF body not read"
    try:
        reader = PdfReader(io.BytesIO(payload))
        pages = [(p.extract_text() or "") for p in reader.pages[:MAX_PDF_PAGES]]
    except Exception as e:
        return "", f"PDF could not be parsed: {type(e).__name__}"
    text = "\n".join(pages).strip()
    if not text:
        # Scanned circulars are images in a PDF wrapper. Saying so is the point:
        # an empty body here means "not readable", not "nothing was published".
        return "", "PDF has no extractable text (likely scanned images)"
    return text[:MAX_PDF_CHARS], ""


def collect(url: str, name: str, fetcher: Fetcher, store: Store,
            link_pattern: str = "", source_type: str = "regulatory",
            limit: int = 20, errors: list[str] | None = None) -> list[Item]:
    """Diff one listing page. Returns items for links not previously seen."""
    errors = errors if errors is not None else []
    source = f"web:{name}"

    res = fetcher.get(url)
    if not res.ok:
        errors.append(f"{source}: {res.error or f'HTTP {res.status}'}")
        return []

    parser = _Links()
    try:
        parser.feed(res.html)
    except Exception as e:
        errors.append(f"{source}: could not parse HTML ({type(e).__name__})")
        return []

    try:
        pattern = re.compile(link_pattern) if link_pattern else None
    except re.error as e:
        errors.append(f"{source}: bad link_pattern {link_pattern!r} ({e})")
        return []

    listing_host = urlparse(url).netloc
    out: list[Item] = []
    seen_here: set[str] = set()

    for href, anchor in parser.links:
        absolute = urljoin(url, href.strip())
        if not absolute.startswith(("http://", "https://")):
            continue
        if pattern and not pattern.search(absolute):
            continue
        # Off-site links on a regulator's page are almost always navigation or
        # a ministry footer, never the circular you came for.
        if urlparse(absolute).netloc != listing_host:
            continue
        if absolute in seen_here or store.is_seen(absolute):
            continue
        seen_here.add(absolute)

        item = Item(
            url=absolute, source=source, source_type=source_type,
            title=anchor[:300],
            raw_meta={"listing": url, "anchor": anchor[:300]},
        )

        doc = fetcher.get(absolute)
        if not doc.ok:
            item.raw_meta["fetch_error"] = doc.error or f"HTTP {doc.status}"
        elif (doc.content_type or "").startswith("application/pdf") \
                or absolute.lower().endswith(".pdf"):
            text, note = _pdf_text(doc.content or b"")
            item.text = text
            item.raw_meta["format"] = "pdf"
            if note:
                item.raw_meta["extract_note"] = note
        else:
            data = extract(doc.html, absolute)
            item.text = data["text"]
            item.title = data["title"] or item.title
            item.author = data["author"]
            item.published_at = data["published_at"]
            item.lang = data["lang"]

        out.append(item)
        if len(out) >= limit:
            break

    return out
