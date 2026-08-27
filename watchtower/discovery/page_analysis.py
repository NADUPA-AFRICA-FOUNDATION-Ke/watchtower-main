from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin
from typing import Any

from investigation.extraction import extract_entities
from investigation.models import Entity
from investigation.normalization import normalize_url


ANALYTICS_PATTERNS = {
    "google_analytics": re.compile(r"\b(?:UA-\d{4,}-\d+|G-[A-Z0-9]{6,})\b", re.I),
    "google_tag_manager": re.compile(r"\bGTM-[A-Z0-9]{5,}\b", re.I),
    "meta_pixel": re.compile(r"fbq\s*\(\s*['\"]init['\"]\s*,\s*['\"](\d{6,})", re.I),
}
PAYMENT_PATTERNS = {
    "paybill": re.compile(r"(?:pay\s?bill|business\s*(?:no|number))\D{0,15}(\d{5,8})", re.I),
    "till": re.compile(r"(?:till|buy\s?goods)\D{0,15}(\d{5,8})", re.I),
}


@dataclass
class PageAnalysis:
    title: str = ""
    description: str = ""
    headings: list[str] = field(default_factory=list)
    visible_text: str = ""
    links: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    images: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    entities: list[Entity] = field(default_factory=list)
    html_fingerprint: str = ""
    analytics_ids: list[str] = field(default_factory=list)
    credential_fields: list[str] = field(default_factory=list)
    favicon_url: str = ""
    simhash: int = 0


class _Parser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(); self.base = base_url
        self.title: list[str] = []; self.headings: list[str] = []
        self.text: list[str] = []; self.links: list[str] = []
        self.scripts: list[str] = []; self.images: list[str] = []
        self.forms: list[dict[str, Any]] = []; self.description = ""
        self.favicon = ""
        self._title = False; self._heading = False; self._skip = 0
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag in {"script", "style", "noscript"}:
            self._skip += 1
        if tag == "title": self._title = True
        if tag in {"h1", "h2", "h3"}: self._heading = True
        if tag == "meta" and values.get("name", "").lower() == "description":
            self.description = values.get("content", "")[:1000]
        if tag == "link" and "icon" in values.get("rel", "").lower() and values.get("href"):
            self.favicon = urljoin(self.base, values["href"])
        if tag in {"a", "iframe"} and values.get("href" if tag == "a" else "src"):
            self.links.append(urljoin(self.base, values.get("href") or values.get("src")))
        if tag == "script" and values.get("src"):
            self.scripts.append(urljoin(self.base, values["src"]))
        if tag == "img" and values.get("src"):
            self.images.append(urljoin(self.base, values["src"]))
        if tag == "form":
            self._form = {"action": urljoin(self.base, values.get("action", "")), "method": values.get("method", "get").lower(), "inputs": []}
            self.forms.append(self._form)
        if tag == "input" and self._form is not None:
            self._form["inputs"].append({k: values.get(k, "") for k in ("name", "type", "autocomplete", "placeholder")})

    def handle_endtag(self, tag):
        if tag in {"script", "style", "noscript"}: self._skip = max(0, self._skip - 1)
        if tag == "title": self._title = False
        if tag in {"h1", "h2", "h3"}: self._heading = False
        if tag == "form": self._form = None

    def handle_data(self, data):
        value = " ".join(data.split())
        if not value or self._skip: return
        self.text.append(value)
        if self._title: self.title.append(value)
        if self._heading: self.headings.append(value)


def analyze_page(html: str, url: str) -> PageAnalysis:
    parser = _Parser(url); parser.feed(html or "")
    visible = " ".join(parser.text)
    links = []
    for link in parser.links:
        try: links.append(normalize_url(link))
        except ValueError: continue
    entities = extract_entities(" ".join((*links, visible, html or "")), url)
    analytics = []
    for kind, pattern in ANALYTICS_PATTERNS.items():
        for match in pattern.findall(html or ""):
            value = match if isinstance(match, str) else match[0]
            canonical = f"{kind}:{str(value).lower()}"
            analytics.append(canonical)
            entities.append(Entity("analytics_id", canonical, str(value)))
    for kind, pattern in PAYMENT_PATTERNS.items():
        for value in pattern.findall(visible):
            entities.append(Entity("payment_identifier", f"{kind}:{value}", value,
                                   metadata={"payment_type": kind}))
    sensitive = {"password", "tel", "email", "number"}
    credential_fields = []
    for form in parser.forms:
        for field in form["inputs"]:
            blob = " ".join(field.values()).lower()
            if field["type"].lower() in sensitive or any(x in blob for x in
                    ("pin", "otp", "national id", "card", "mobile", "phone")):
                credential_fields.append(blob)
    normalized_html = re.sub(r"\s+", " ", re.sub(r">[^<]+<", "><", html or "")).strip().lower()
    fingerprint = hashlib.sha256(normalized_html.encode()).hexdigest()
    entities.append(Entity("html_fingerprint", "sha256:" + fingerprint, fingerprint))
    tokens = re.findall(r"[a-z0-9]{3,}", visible.lower())
    vector = [0] * 64
    for token in tokens[:5000]:
        value = int.from_bytes(hashlib.blake2b(token.encode(), digest_size=8).digest(), "big")
        for bit in range(64): vector[bit] += 1 if value & (1 << bit) else -1
    simhash = sum(1 << bit for bit, weight in enumerate(vector) if weight >= 0)
    return PageAnalysis(
        " ".join(parser.title), parser.description, parser.headings[:20], visible[:50000],
        sorted(set(links)), sorted(set(parser.scripts)), sorted(set(parser.images)),
        parser.forms, entities, fingerprint, sorted(set(analytics)),
        sorted(set(credential_fields)), parser.favicon or urljoin(url, "/favicon.ico"), simhash,
    )
