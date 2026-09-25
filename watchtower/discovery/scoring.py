from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import re
from urllib.parse import urlsplit

from scamscan import impersonation_score


FREE_HOST_SUFFIXES = (
    "vercel.app", "netlify.app", "lovable.app", "firebaseapp.com",
    "web.app", "github.io", "pages.dev", "000webhostapp.com",
)


def _host_is(host: str, suffix: str) -> bool:
    host = host.lower().rstrip(".")
    suffix = suffix.lower().rstrip(".")
    return host == suffix or host.endswith("." + suffix)


def _hosting_signal(entity) -> str:
    domain = entity.canonical_value
    for suffix in FREE_HOST_SUFFIXES:
        if _host_is(domain, suffix):
            return suffix
    # Custom domains often retain a CNAME to the deployment platform.
    cnames = entity.metadata.get("dns", {}).get("CNAME", [])
    for cname in cnames:
        value = str(cname).lower().rstrip(".")
        if any(token in value for token in (
            "vercel-dns.com", "netlify.com", "lovable.app",
            "pages.dev", "firebaseapp.com",
        )):
            return value
    return ""


def _mentions_brand(text: str, brand_config: dict) -> bool:
    folded = re.sub(r"[^a-z0-9]", "", (text or "").lower())
    terms = [brand_config.get("name", ""), *brand_config.get("aliases", []),
             *brand_config.get("products", [])]
    return any(
        len(needle) >= 4 and needle in folded
        for term in terms
        if (needle := re.sub(r"[^a-z0-9]", "", str(term).lower()))
    )


@dataclass
class EvidenceScore:
    risk_score: float
    confidence: float
    machine_verdict: str
    evidence_count: int
    strongest_evidence: list[str] = field(default_factory=list)
    contradictory_evidence: list[str] = field(default_factory=list)
    categories: dict[str, float] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)
    scoring_version: str = "evidence-v3"
    factors: list[dict] = field(default_factory=list)

    def dict(self):
        return asdict(self)


def _official(domain: str, official_domains) -> bool:
    domain = domain.lower().rstrip(".")
    return any(domain == item.lower().rstrip(".") for item in official_domains)


def score_domain(entity, evidence, relationships, entities, brand_config) -> EvidenceScore:
    """Score observed evidence with hosting risk conditional on brand signals."""
    domain = entity.canonical_value
    if _official(domain, brand_config.get("official_domains", [])):
        return EvidenceScore(0, 1.0, "LEGITIMATE", len(evidence), [],
                             ["Exact verified official domain"], {},
                             sorted({e.source for e in evidence}))
    categories = {
        "brand_impersonation": 0.0,
        "credential_harvesting": 0.0,
        "threat_intelligence": 0.0,
        "payment_identifiers": 0.0,
        "social_relationships": 0.0,
        "campaign_correlation": 0.0,
        "domain_characteristics": 0.0,
        "hosting_risk": 0.0,
        "redirect_behavior": 0.0,
    }
    strongest = []
    contradictory = []
    finding = {"url": f"https://{domain}/"}
    imp, reason = impersonation_score(finding["url"], brand_config)
    categories["brand_impersonation"] = min(45, imp * 0.50)
    if imp >= 70:
        strongest.append(f"Domain resembles or contains the protected brand: {reason}")
    page = entity.metadata.get("page", {})
    page_text = " ".join((page.get("title", ""), page.get("description", ""),
                          page.get("visible_text", ""))).lower()
    discovery_text = " ".join(
        str(value)
        for item in evidence
        if item.evidence_type in {"discovery", "reverse_pivot"}
        for value in (
            item.raw_metadata.get("title", ""),
            item.raw_metadata.get("snippet", ""),
            item.observed_value or "",
        )
    )
    hosting = _hosting_signal(entity)
    hosted_brand_content = bool(hosting) and _mentions_brand(
        page_text + " " + discovery_text, brand_config
    )
    if hosted_brand_content:
        categories["brand_impersonation"] = max(
            categories["brand_impersonation"], 25
        )
        strongest.append("Hosted page or search evidence mentions the protected brand")
    # Shared hosting is not suspicious by itself. It becomes meaningful only
    # when the hostname or observed content matches the protected brand.
    if hosting and (imp >= 40 or hosted_brand_content):
        categories["hosting_risk"] = 25
        strongest.append(f"Brand-matching site uses easily-created hosting: {hosting}")
    if any(term in page_text for term in (
        "never share your pin", "fraud awareness", "scam alert",
        "how to avoid", "public notice", "press release",
    )):
        contradictory.append("Page appears to be anti-fraud, news, or advisory content")
    sensitive = page.get("credential_fields", [])
    if sensitive:
        categories["credential_harvesting"] = min(35, 20 + 5 * len(sensitive))
        strongest.append("Page contains fields associated with credentials or identity data")
    threat = entity.metadata.get("threat_intelligence", {})
    if threat.get("matches"):
        categories["threat_intelligence"] = 50
        strongest.append("Public threat-intelligence provider reports a match")
    registration = entity.metadata.get("rdap", {}).get("registration_date")
    if registration:
        try:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(
                registration.replace("Z", "+00:00"))).days
            if 0 <= age <= 30:
                categories["domain_characteristics"] = 15
                strongest.append(f"Domain registration observed {max(age, 0)} days ago")
            elif 30 < age <= 180:
                categories["domain_characteristics"] = 8
        except (TypeError, ValueError):
            pass
    outgoing = [r for r in relationships if r.source_entity_id == entity.id]
    targets = [entities.get(r.target_entity_id) for r in outgoing]
    payments = [x for x in targets if x and x.entity_type == "payment_identifier"]
    socials = [x for x in targets if x and x.entity_type in {"social_account", "phone_number"}]
    if payments:
        categories["payment_identifiers"] = min(20, 10 + len(payments) * 5)
        strongest.append("Page exposes a mobile-money or payment identifier")
    if socials:
        categories["social_relationships"] = min(15, 5 + len(socials) * 3)
    correlated = [r for r in relationships if entity.id in
                  {r.source_entity_id, r.target_entity_id} and r.relationship_type.startswith("shares_")]
    if correlated:
        categories["campaign_correlation"] = min(25, 10 + 5 * len(correlated))
        strongest.append("Exact identifier reuse connects this domain to other candidates")
    redirects = page.get("redirect_chain", [])
    if len({urlsplit(x).hostname for x in redirects if urlsplit(x).hostname}) > 1:
        categories["redirect_behavior"] = 10
        strongest.append("Page redirects across domain boundaries")
    score = min(100.0, round(sum(categories.values()), 1))
    if contradictory and not categories["credential_harvesting"]:
        score = max(0.0, score - 30)
    substantive = sum(1 for value in categories.values() if value > 0)
    observed_sources = sorted({e.source for e in evidence})
    confidence = min(1.0, round(0.2 + 0.12 * substantive + 0.05 * len(observed_sources), 2))
    if categories["threat_intelligence"] and categories["credential_harvesting"]:
        verdict = "LIKELY_IMPERSONATION"
    elif score >= 70 and substantive >= 3:
        verdict = "LIKELY_IMPERSONATION"
    elif score >= 45 and substantive >= 2:
        verdict = "SUSPICIOUS"
    elif score >= 20:
        verdict = "WATCHLIST"
    else:
        verdict = "INSUFFICIENT_EVIDENCE"
    factor_types = {
        "brand_impersonation": {"discovery", "investigation_seed", "page_inspection"},
        "credential_harvesting": {"page_inspection"},
        "threat_intelligence": {"threat_intelligence"},
        "domain_characteristics": {"rdap_observation"},
        "hosting_risk": {"discovery", "investigation_seed", "dns_observation", "page_inspection"},
        "redirect_behavior": {"page_inspection", "redirect_observation"},
        "social_relationships": {"page_observation", "social_index_observation"},
        "payment_identifiers": {"page_observation"},
    }
    factors = []
    for factor, points in categories.items():
        if points <= 0:
            continue
        ids = [ev.id for ev in evidence if (
            ev.evidence_type in factor_types.get(factor, set()) or
            factor == "campaign_correlation" and ev.evidence_type.startswith("shares_")
        )]
        factors.append({"factor": factor, "score": points, "evidence_ids": sorted(set(ids)),
                        "basis": "observed" if ids else "unpersisted input; not an evidence-backed conclusion"})
    return EvidenceScore(score, confidence, verdict, len(evidence), strongest[:6], contradictory,
                         categories, observed_sources, factors=factors)
