"""
osint_discovery - Active internet hunting for scam websites.

This module searches the internet for potential scam sites using:
1. Search engine dorks targeting free hosting providers
2. Certificate Transparency logs for newly issued certificates
3. Social media and forum monitoring
4. Automatic verification through existing scam detection engine

Usage:
  python scamscan.py discover --config config.json --limit 10
  python scamscan.py discover --config config.json --source ct --brand fuliza
  python scamscan.py discover --config config.json --dry-run
"""

import argparse
import copy
import json
import logging
import re
import sys
import time
from datetime import datetime, timezone
from urllib.parse import quote_plus

try:
    from ddgs import DDGS
except ImportError:
    try:
        from duckduckgo_search import DDGS
    except ImportError:
        DDGS = None

# Import from scamscan module
from scamscan import (
    load_env, score_finding, db_connect, upsert, 
    impersonation_score, extract_artifacts, lexicon_score,
    registrable
)

load_env()

logger = logging.getLogger(__name__)

# Free hosting providers commonly used for scam sites
FREE_HOSTS = [
    "vercel.app",
    "netlify.app",
    "netlify.com",
    "firebaseapp.com",
    "web.app",
    "github.io",
    "pages.dev",
    "000webhostapp.com",
    "infinityfreeapp.com",
    "rf.gd",
    "epizy.com",
    "ucoz.com",
    "blogspot.com",
    "wordpress.com",
    "wixsite.com",
    "mysite.com",
    "site123.me",
    "jimdosite.com",
    "weebly.com",
    "strikingly.com",
    "carrd.co",
    "linktr.ee",
    "bit.ly",
    "tinyurl.com",
]

# Search query templates
SEARCH_TEMPLATES = [
    # Google Dorks for free hosting with brand keywords
    'site:vercel.app "{brand}"',
    'site:netlify.app "{brand}"',
    'site:firebaseapp.com "{brand}"',
    'site:web.app "{brand}"',
    'site:github.io "{brand}"',
    'site:pages.dev "{brand}"',
    
    # Financial scam patterns on free hosts
    'site:vercel.app "{brand}" limit boost',
    'site:vercel.app "{brand}" loan',
    'site:vercel.app "{brand}" activation',
    'site:netlify.app "{brand}" verify',
    'site:firebaseapp.com "{brand}" login',
    
    # Generic scam patterns
    '"{brand}" "processing fee"',
    '"{brand}" "activation fee"',
    '"{brand}" "send pin"',
    '"{brand}" "confirm your"',
    '"{brand}" "customer care"',
    '"{brand}" "verified agent"',
    
    # URL patterns
    'inurl:{brand} inurl:login',
    'inurl:{brand} inurl:verify',
    'inurl:{brand} inurl:boost',
    'inurl:{brand} inurl:limit',
    'inurl:{brand} inurl:loan',
]


def lexicon_query_terms(cfg, limit=12):
    """Return strong, sourced bait phrases for discovery queries.

    The lexicon used to influence ranking only *after* a search engine happened
    to return a candidate.  That left most of its carefully sourced language
    idle during discovery.  Prefer high-weight phrases, but round-robin across
    languages so English cannot consume the entire query budget.  Unverified
    terms remain useful for scoring, but are too weak a basis for spending a
    search request.
    """
    by_language = []
    for language, entries in cfg.get("lexicon", {}).items():
        candidates = []
        for term, entry in entries.items():
            if isinstance(entry, (list, tuple)):
                weight = float(entry[0]) if entry else 0
                source = str(entry[1]) if len(entry) > 1 else ""
            else:  # Backwards-compatible with older, bare-number lexicons.
                weight, source = float(entry), ""
            clean_term = term.strip()
            if (weight >= 20 and source != "UNVERIFIED"
                    and len(clean_term) >= 6
                    and clean_term[0].isalnum()
                    and clean_term[-1].isalnum()):
                candidates.append((weight, term.strip()))
        candidates.sort(key=lambda item: (-item[0], item[1]))
        if candidates:
            by_language.append([term for _, term in candidates])

    selected = []
    while len(selected) < limit and any(by_language):
        for terms in by_language:
            if terms and len(selected) < limit:
                selected.append(terms.pop(0))
    return selected

# Certificate Transparency query endpoints
CT_SEARCH_URL = "https://crt.sh/?q=%.{domain}&output=json"


class DiscoveryError(RuntimeError):
    """A search could not run; distinct from a successful zero-result search."""


def generate_queries(cfg, brand_keyword=None):
    """Generate search queries based on brand aliases and search templates."""
    brand = cfg.get("brand", {})
    aliases = brand.get("aliases", [])
    
    # Use specific brand keyword if provided, otherwise use main aliases
    if brand_keyword:
        keywords = [brand_keyword]
    else:
        # Prioritize high-value keywords
        keywords = []
        for alias in aliases:
            alias_lower = alias.lower()
            # Prioritize financial product names and brand names
            if any(term in alias_lower for term in ["fuliza", "shwari", "kcb", "tala", "branch", "zenka"]):
                keywords.insert(0, alias)
            elif len(alias.split()) <= 2:  # Short aliases are better for search
                keywords.append(alias)
        
        # Ensure we have at least the main brand name
        if not keywords and aliases:
            keywords = aliases[:5]
        else:
            keywords = keywords[:10]  # Limit to avoid rate limits
    
    queries = []
    seen = set()

    # Search for the language the detector can actually recognise, not just a
    # small hard-coded English subset. Parentheses distinguish this family in
    # select_queries(), where it receives its own share of the request budget.
    for keyword in keywords:
        clean_keyword = keyword.replace('"', '').strip()
        if not clean_keyword:
            continue
        for term in lexicon_query_terms(cfg):
            clean_term = term.replace('"', '').strip()
            query = f'"{clean_keyword}" ("{clean_term}")'
            if query not in seen:
                seen.add(query)
                queries.append(query)
    
    for template in SEARCH_TEMPLATES:
        for keyword in keywords:
            # Clean keyword for search
            clean_keyword = keyword.replace('"', '').strip()
            if not clean_keyword:
                continue
                
            query = template.format(brand=clean_keyword)
            
            # Avoid duplicates
            if query not in seen:
                seen.add(query)
                queries.append(query)
    
    return queries


def select_queries(queries, limit=10):
    """Choose a small but diverse set instead of only the first host dorks.

    ``generate_queries`` is grouped by template.  Taking its first few entries
    over-sampled generic free-host searches and never reached fee, credential,
    or URL-pattern searches—the strongest discovery signals.
    """
    groups = ([], [], [], [], [])
    for query in queries:
        if query.startswith("inurl:"):
            groups[3].append(query)
        elif '("' in query:
            groups[4].append(query)
        elif query.startswith("site:") and any(
                token in query for token in (" limit ", " loan", " activation",
                                             " verify", " login")):
            groups[1].append(query)
        elif query.startswith("site:"):
            groups[0].append(query)
        else:
            groups[2].append(query)

    selected = []
    while len(selected) < limit and any(groups):
        for group in groups:
            if group and len(selected) < limit:
                selected.append(group.pop(0))
    return selected


def search_duckduckgo(query, max_results=10):
    """Search DuckDuckGo and return results."""
    if DDGS is None:
        raise DiscoveryError(
            "DuckDuckGo search is unavailable; install the 'ddgs' dependency")
    
    try:
        results = []
        with DDGS() as ddgs:
            # DuckDuckGo search
            search_results = list(ddgs.text(query, max_results=max_results))
            
            for r in search_results:
                if isinstance(r, dict):
                    results.append({
                        "title": r.get("title", ""),
                        "url": r.get("href", r.get("url", "")),
                        "summary": r.get("body", r.get("snippet", "")),
                        "source": "duckduckgo",
                        "query": query,
                    })
                elif isinstance(r, str):
                    # Some versions return just URLs
                    results.append({
                        "title": "",
                        "url": r,
                        "summary": "",
                        "source": "duckduckgo",
                        "query": query,
                    })
        
        return results
    except Exception as e:
        raise DiscoveryError(f"DuckDuckGo search failed for query {query!r}: {e}") from e


def check_certificate_transparency(domain_pattern, max_results=20, official_domains=None):
    """Query Certificate Transparency logs for certificates matching pattern."""
    import urllib.request
    import ssl
    
    try:
        url = CT_SEARCH_URL.format(domain=quote_plus(domain_pattern))
        
        # Create SSL context that doesn't verify (for crt.sh which uses self-signed)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; ScamScan/1.0)"}
        )
        
        with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
            data = response.read().decode("utf-8", errors="ignore")
            
        # Parse JSON response
        certs = json.loads(data) if data.strip() else []
        
        results = []
        seen_domains = set()
        
        for cert in certs[:max_results]:
            # Extract domain names from certificate
            name = cert.get("name_value", "")
            domains = name.split("\n")
            
            for domain in domains:
                domain = domain.strip().lower()
                if domain and domain not in seen_domains:
                    # Skip wildcards and already-known-good domains
                    if domain.startswith("*."):
                        domain = domain[2:]
                    
                    if domain in seen_domains:
                        continue
                    
                    seen_domains.add(domain)
                    
                    # Skip official domains (passed as parameter)
                    if any(domain.endswith(odom.lower()) for odom in (official_domains or [])):
                        continue
                    
                    # Construct potential URLs
                    if not domain.startswith(("http://", "https://")):
                        url = f"https://{domain}"
                    else:
                        url = domain
                    
                    results.append({
                        "title": f"Certificate: {domain}",
                        "url": url,
                        "summary": f"Domain found in CT logs matching {domain_pattern}",
                        "source": "certificate_transparency",
                        "query": domain_pattern,
                        "cert_info": {
                            "issuer": cert.get("issuer_name", ""),
                            "registered": cert.get("entry_timestamp", ""),
                        }
                    })
        
        return results
    except Exception as e:
        logger.error(f"CT search failed for '{domain_pattern}': {e}")
        return []


def evaluate_url(url, title, summary, cfg):
    """Evaluate a discovered URL using the existing scoring system."""
    # Combine all available text for scoring
    full_text = f"{title or ''} {summary or ''}"
    
    # Create a finding structure compatible with score_finding
    finding = {
        "url": url,
        "title": title or "",
        "summary": full_text,
        "quoted_evidence": full_text,
        "model_confidence": None,  # Will be ignored in scoring
    }
    
    # Score using local heuristics
    scored = score_finding(finding, cfg)
    
    return scored


def fetch_and_analyze_url(url, cfg):
    """Fetch and analyze a single URL for the web API."""
    import re
    from urllib.parse import urlparse
    
    # Fetch the URL content
    try:
        from core.fetch import Fetcher
        fetcher = Fetcher(
            user_agent="Mozilla/5.0 (compatible; FraudGuard/1.0)",
            delay=0,
            timeout=20,
            obey_robots=False
        )
        
        # Fetch page content - use .get() method which returns FetchResult
        result = fetcher.get(url)
        html_content = result.html if result.ok else ""
        
        # Extract text from HTML (simple approach)
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Remove script and style elements
        for script in soup(['script', 'style']):
            script.decompose()
        
        text = soup.get_text(separator=' ', strip=True)[:10000]
        title = soup.title.string if soup.title else ""
        
        # Create finding structure
        finding = {
            "url": url,
            "title": title or "",
            "summary": text,
            "quoted_evidence": text[:2000],
            "model_confidence": None,
        }
        
        # --- CRITICAL HEURISTICS (Override AI) ---
        full_text = (title + " " + text).lower()
        
        # 1. INSTANT SCAM DETECTION: Payment/Fee Requests for Official Services
        payment_triggers = [
            r"pay\s+(to|for)\s+(unlock|activate|boost|increase)",
            r"(processing|activation|registration|insurance)\s+fee",
            r"send\s+(money|cash|mpesa|lipa)\s+to\s+(number|code|till)",
            r"pay\s+ksh\s+\d+",
            r"mpesa\s+payment\s+required",
            r"confirm\s+payment\s+to\s+release",
            r"fee\s+of\s+ksh",
            r"pay\s+now\s+to\s+get",
            r"complete\s+a\s+secure\s+payment",
            r"continue\s+to\s+payment"
        ]
        
        for pattern in payment_triggers:
            if re.search(pattern, full_text, re.IGNORECASE):
                finding["_smoking_gun"] = True
                finding["_smoking_gun_reason"] = "CRITICAL: Site requests payment/fees for service activation (Definitive Scam Indicator)"
                break
        
        # 2. OFFICIAL DOMAIN CHECK
        official_domains = cfg.get("brand", {}).get("official_domains", [])
        parsed = urlparse(url)
        hostname = parsed.netloc.lower()
        
        for official in official_domains:
            if hostname == official or hostname.endswith("." + official):
                finding["_is_official"] = True
                finding["_official_domain"] = official
                break
        
        return finding
        
    except Exception as e:
        # Return minimal finding with error info
        return {
            "url": url,
            "title": "",
            "summary": f"Error fetching URL: {str(e)}",
            "quoted_evidence": "",
            "model_confidence": None,
        }


def discover_and_score(brand, limit, cfg):
    """Discover scams for a brand and return scored results."""
    results = []
    seen_urls = set()
    
    # Generate queries for this brand
    # This endpoint is called repeatedly by the UI.  A shallow copy used to
    # mutate the cached application config, leaking one scan's brand into every
    # later scan and making ratings depend on request order.
    brand_cfg = copy.deepcopy(cfg)
    brand_cfg["brand"]["name"] = brand
    brand_cfg["brand"]["aliases"] = list(dict.fromkeys(
        [brand] + cfg["brand"].get("aliases", [])))
    
    queries = generate_queries(brand_cfg, brand_keyword=brand)
    
    # Search across hosting, scam-copy and URL-pattern query families.  Gather
    # more candidates than requested because ranking happens after dedupe.
    failures = []
    searched = 0
    candidate_cap = max(limit * 4, limit)
    for query in select_queries(queries):
        try:
            search_results = search_duckduckgo(
                query, max_results=min(limit * 2, 20))
            searched += 1
        except DiscoveryError as exc:
            failures.append(str(exc))
            continue
        
        for result in search_results:
            url = result.get('url', '')
            
            # Skip already processed URLs
            if url in seen_urls:
                continue
            seen_urls.add(url)
            
            # Skip known safe domains using the trusted_domains module
            from core.trusted_domains import is_trusted_domain
            from urllib.parse import urlparse
            
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            if is_trusted_domain(domain):
                logger.debug(f"Skipping trusted domain: {domain}")
                continue
            
            # Evaluate the URL
            title = result.get('title', '')
            # search_duckduckgo normalises snippets under ``summary``.  Reading
            # the nonexistent ``description`` key discarded nearly all content
            # evidence and left the URL alone to determine the rating.
            summary = result.get('summary', '')
            
            scored = evaluate_url(url, title, summary, brand_cfg)
            
            results.append({
                "url": url,
                "title": title,
                "summary": summary,
                "score": scored.get("score", 0),
                "scam_type": scored.get("scam_type", "unknown"),
                "source": result.get("source", "duckduckgo"),
                "query": query,
                "breakdown": scored,
            })
            
            if len(results) >= candidate_cap:
                break
        
        if len(results) >= candidate_cap:
            break

    if not searched:
        raise DiscoveryError(
            "No OSINT query could be searched. " + "; ".join(failures[:3]))
    
    # Sort by score descending
    results.sort(key=lambda x: x["score"], reverse=True)
    
    return results[:limit]


def discover(cfg, limit=20, source="all", brand_keyword=None, dry_run=False):
    """Main discovery function."""
    results = []
    seen_urls = set()
    
    # Generate search queries
    queries = generate_queries(cfg, brand_keyword)
    query_plan = select_queries(queries, limit=min(20, len(queries)))
    
    logger.info(f"Generated {len(queries)} search queries")
    
    if dry_run:
        print(f"\n=== DRY RUN: Would execute {len(query_plan)} queries ===\n")
        for i, q in enumerate(query_plan[:10], 1):
            print(f"{i}. {q}")
        if len(query_plan) > 10:
            print(f"... and {len(query_plan) - 10} more")
        return []
    
    # Search based on source type
    all_findings = []
    
    if source in ("all", "search"):
        logger.info("Running search engine queries...")
        for i, query in enumerate(query_plan):
            if limit and len(all_findings) >= limit * 2:  # Get extra for filtering
                break
                
            logger.debug(f"Searching: {query}")
            search_results = search_duckduckgo(query, max_results=5)
            
            for r in search_results:
                url = r.get("url", "")
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    all_findings.append(r)
            
            # Rate limiting
            time.sleep(0.5)
    
    if source in ("all", "ct"):
        logger.info("Checking Certificate Transparency logs...")
        brand = cfg.get("brand", {})
        aliases = brand.get("aliases", [])
        
        # Check CT for each brand alias
        for alias in aliases[:5]:  # Limit CT queries
            clean_alias = re.sub(r'[^a-z0-9]', '', alias.lower())
            if len(clean_alias) < 3:
                continue
                
            ct_results = check_certificate_transparency(clean_alias, max_results=10)
            
            for r in ct_results:
                url = r.get("url", "")
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    all_findings.append(r)
            
            time.sleep(1.0)  # CT API rate limiting
    
    # Evaluate and score findings
    logger.info(f"Evaluating {len(all_findings)} unique URLs...")
    
    con = None
    if not dry_run:
        con = db_connect()
    
    for finding in all_findings:
        url = finding.get("url", "")
        
        # Skip blocked/official domains
        blocked = cfg.get("search", {}).get("blocked_domains", [])
        if any(registrable(url).endswith(bd) for bd in blocked):
            continue
        
        # CRITICAL: Skip trusted domains (chatgpt.com, openai.com, google.com, etc.)
        from core.trusted_domains import is_trusted_domain
        from urllib.parse import urlparse
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        if is_trusted_domain(domain):
            logger.debug(f"Skipping trusted domain during OSINT discovery: {domain}")
            continue
        
        # Score the finding
        scored = evaluate_url(
            url,
            finding.get("title", ""),
            finding.get("summary", ""),
            cfg
        )
        
        # Only keep findings above threshold
        threshold = cfg.get("scoring", {}).get("review_threshold", 45)
        if scored["score"] >= threshold:
            result = {
                "url": url,
                "title": finding.get("title", ""),
                "summary": finding.get("summary", ""),
                "source": finding.get("source", "unknown"),
                "query": finding.get("query", ""),
                "score": scored["score"],
                "breakdown": scored,
                "discovered_at": datetime.now(timezone.utc).isoformat(),
            }
            results.append(result)
            
            # Store in database
            if con and not dry_run:
                upsert(con, finding, scored, finding.get("query", "discover"))
            
            logger.info(f"FOUND: {url} (score: {scored['score']})")
    
    if con:
        con.commit()
        con.close()
    
    # Sort by score descending
    results.sort(key=lambda x: x["score"], reverse=True)
    
    return results[:limit]


def cmd_discover(args):
    """Command handler for discover."""
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s"
    )
    
    # Load config
    cfg = json.load(open(args.config))
    
    results = discover(
        cfg,
        limit=args.limit,
        source=args.source,
        brand_keyword=args.brand,
        dry_run=args.dry_run
    )
    
    if args.dry_run:
        return 0
    
    # Output results
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"\n{'='*80}")
        print(f"DISCOVERED {len(results)} POTENTIAL SCAM SITES")
        print(f"{'='*80}\n")
        
        for i, r in enumerate(results, 1):
            print(f"[{i}] Score: {r['score']} | Source: {r['source']}")
            print(f"    URL: {r['url']}")
            if r.get('title'):
                print(f"    Title: {r['title']}")
            if r.get('summary'):
                summary = r['summary'][:200] + "..." if len(r['summary']) > 200 else r['summary']
                print(f"    Summary: {summary}")
            
            bd = r.get('breakdown', {})
            print(f"    Breakdown: lexicon={bd.get('lexicon_score', 0)}, "
                  f"artifact={bd.get('artifact_score', 0)}, "
                  f"impersonation={bd.get('impersonation_score', 0)}")
            
            if bd.get('artifacts'):
                print(f"    Artifacts: {bd['artifacts']}")
            
            print()
    
    return 0


def add_discover_parser(subparsers):
    """Add discover command to argument parser."""
    d = subparsers.add_parser("discover", help="actively hunt for scam websites")
    d.add_argument("--config", default="config.json")
    d.add_argument("--limit", type=int, default=20, help="max results to return")
    d.add_argument("--source", choices=["all", "search", "ct"], default="all",
                   help="discovery source: all, search (engine), ct (certificates)")
    d.add_argument("--brand", help="specific brand keyword to search for")
    d.add_argument("--dry-run", action="store_true",
                   help="show queries without executing")
    d.add_argument("--json", action="store_true", help="output as JSON")
    d.add_argument("-v", "--verbose", action="store_true")
    d.set_defaults(func=cmd_discover)
