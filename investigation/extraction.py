from __future__ import annotations

import re
from html import unescape
from urllib.parse import urljoin, urlsplit

from .models import Entity
from .normalization import (
    normalize_domain,
    normalize_phone,
    normalize_social,
    normalize_url,
)

SOCIAL = {
    "tiktok.com": ("tiktok", r"^/@?([^/?#]+)"),
    "instagram.com": ("instagram", r"^/([^/?#]+)"),
    "facebook.com": ("facebook", r"^/([^/?#]+)"),
    "x.com": ("x", r"^/([^/?#]+)"),
    "twitter.com": ("x", r"^/([^/?#]+)"),
    "t.me": ("telegram", r"^/([^/?#]+)"),
    "youtube.com": ("youtube", r"^/@?([^/?#]+)"),
    "bsky.app": ("bluesky", r"^/profile/([^/?#]+)"),
    "reddit.com": ("reddit", r"^/(?:u|user)/([^/?#]+)"),
}
COMMON = {"google.com", "gstatic.com", "cloudflare.com", "cdnjs.cloudflare.com"}
URL_RE = re.compile(r"https?://[^\s<'\"()]+", re.I)
EMAIL_RE = re.compile(
    r"(?<![\w.-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w-])", re.I
)
PHONE_RE = re.compile(r"(?<!\d)(?:\+254|254|0)[\s().-]*[17]\d(?:[\s().-]*\d){7}(?!\d)")


def extract_entities(
    text: str, source_url: str = "", default_region: str | None = "KE"
) -> list[Entity]:
    text = unescape(text or "")
    found: dict[tuple[str, str], Entity] = {}

    def add(entity: Entity):
        found[(entity.entity_type, entity.canonical_value)] = entity

    for match in URL_RE.findall(text):
        raw = match.rstrip(".,;:!]")
        try:
            url = normalize_url(urljoin(source_url, raw))
        except ValueError:
            continue
        p, host = urlsplit(url), normalize_domain(url)
        social = next(
            ((v, k) for k, v in SOCIAL.items() if host == k or host.endswith("." + k)),
            None,
        )
        if host == "wa.me":
            phone = normalize_phone(p.path.strip("/"), default_region)
            if phone:
                add(Entity("phone_number", phone, phone, "whatsapp"))
        elif social:
            (platform, pattern), _ = social
            m = re.match(pattern, p.path)
            if m:
                add(
                    Entity(
                        "social_account",
                        normalize_social(platform, m.group(1)),
                        "@" + m.group(1),
                        platform,
                    )
                )
        elif raw.lower().split("?", 1)[0].endswith(".apk"):
            add(Entity("app", url, raw, metadata={"format": "apk"}))
        elif host and host not in COMMON:
            add(Entity("domain", host, host))
    for email in EMAIL_RE.findall(text):
        add(Entity("email", email.lower(), email))
    for value in PHONE_RE.findall(text):
        phone = normalize_phone(value, default_region)
        if phone:
            add(Entity("phone_number", phone, phone))
    return list(found.values())
