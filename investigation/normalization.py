from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit


def normalize_domain(value: str) -> str:
    raw = value.strip()
    parsed = urlsplit(raw if "://" in raw else "//" + raw)
    host = (parsed.hostname or "").lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def normalize_url(value: str) -> str:
    parsed = urlsplit(value.strip() if "://" in value else "https://" + value.strip())
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("only HTTP(S) URLs are supported")
    host = (parsed.hostname or "").lower().encode("idna").decode("ascii")
    if not host:
        raise ValueError("URL has no hostname")
    port = parsed.port
    netloc = host if port in (None, 80, 443) else f"{host}:{port}"
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))


def normalize_phone(value: str, default_region: str | None = None) -> str | None:
    digits = re.sub(r"\D", "", value)
    if value.strip().startswith("+") and 8 <= len(digits) <= 15:
        return "+" + digits
    if digits.startswith("254") and len(digits) == 12:
        return "+" + digits
    if default_region == "KE" and digits.startswith("0") and len(digits) == 10:
        return "+254" + digits[1:]
    # Local numbers without explicit context are deliberately not guessed.
    return None


def normalize_social(platform: str, handle: str) -> str:
    p = "x" if platform.lower() in {"twitter", "x"} else platform.lower()
    return f"{p}:{handle.strip().lstrip('@').rstrip('/').lower()}"


def is_public_host(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return host.lower() not in {"localhost", "localhost.localdomain"}
