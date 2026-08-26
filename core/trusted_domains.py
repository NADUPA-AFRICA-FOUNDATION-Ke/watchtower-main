"""
Trusted Domain and Infrastructure Whitelist.
Prevents false positives on high-reputation sites that may mention scam keywords.
"""

# Top-level domains and bases that are inherently trusted
TRUSTED_DOMAINS = {
    # Search Engines & Tech Giants
    "google.com",
    "google.co.ke",
    "google.co.tz",
    "google.co.ug",
    "bing.com",
    "yahoo.com",
    
    # AI Platforms (Often discuss scams but are safe)
    "openai.com",
    "chatgpt.com",
    "claude.ai",
    "anthropic.com",
    "gemini.google.com",
    
    # App Stores & Repositories
    "play.google.com",
    "apps.apple.com",
    "github.com",
    "gitlab.com",
    "pypi.org",
    "npmjs.com",
    
    # Social Media (Official domains)
    "facebook.com",
    "fb.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "instagram.com",
    "whatsapp.com",
    "telegram.org",
    "tiktok.com",
    
    # Cloud & Hosting (Official homepages, not user subdomains)
    "vercel.com",
    "netlify.com",
    "aws.amazon.com",
    "cloudflare.com",
    "digitalocean.com",
    "heroku.com",
    "firebase.google.com",
    
    # News & Information (Often report on scams)
    "bbc.com",
    "cnn.com",
    "reuters.com",
    "nation.africa",
    "standardmedia.co.ke",
    "citizen.digital",
    
    # Kenyan/African Official Entities
    "go.ke",
    "gov.ke",
    "gc.ke",
    "ecitizen.go.ke",
    "kra.go.ke",
    "mpesa.co.ke",
    "safaricom.co.ke",
}

# Trusted ASN Organizations (IP ranges that are generally safe for hosting main sites)
# Note: Scammers CAN use these clouds, but the official corporate IPs are safe.
# This is used more for enrichment than hard-blocking.
TRUSTED_ASN_ORGS = {
    "Google LLC",
    "Microsoft Corporation",
    "Apple Inc.",
    "Cloudflare, Inc.",
    "Meta Platforms, Inc.",
    "Amazon.com, Inc.",
}

def is_trusted_domain(domain: str) -> bool:
    """
    Check if a domain is on the trusted whitelist.
    Handles subdomains correctly (e.g., play.google.com -> google.com).
    """
    if not domain:
        return False
    
    domain = domain.lower().strip()
    
    # Exact match
    if domain in TRUSTED_DOMAINS:
        return True
    
    # Check base domains for nested subdomains
    # e.g. "news.blog.google.com" should check against "google.com"
    parts = domain.split('.')
    if len(parts) >= 2:
        # Try progressively shorter domains
        for i in range(len(parts)):
            base = '.'.join(parts[i:])
            if base in TRUSTED_DOMAINS:
                return True
                
    # Check TLD trusts (e.g. anything ending in .gov.ke is trusted)
    if domain.endswith('.gov.ke') or domain.endswith('.go.ke'):
        return True
        
    return False

def get_trust_reason(domain: str) -> str:
    """Return the reason why a domain is trusted."""
    domain = domain.lower()
    if domain in TRUSTED_DOMAINS:
        return "Listed Trusted Domain"
    
    if domain.endswith('.gov.ke') or domain.endswith('.go.ke'):
        return "Government Domain (.gov.ke/.go.ke)"
        
    parts = domain.split('.')
    for i in range(len(parts)):
        if '.'.join(parts[i:]) in TRUSTED_DOMAINS:
            return f"Subdomain of Trusted Domain ({'.'.join(parts[i:])})"
            
    return "Unknown Trust Reason"
