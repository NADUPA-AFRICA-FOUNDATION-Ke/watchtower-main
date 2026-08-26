# Watchtower/ScamScan Improvements Plan

Based on comprehensive security research feedback, this document outlines the transformation from a simple "scam keyword detector" into a proper **evidence-based threat intelligence engine** focused on African financial fraud.

## Core Philosophy Change

**Before:** `suspicious keyword + suspicious domain + suspicious hosting = scam`

**After:** Collect multiple independent pieces of evidence → correlate → risk score → verdict with confidence level

## Evidence Model

For every URL, build an evidence record containing:

### Identity Evidence
- Domain
- URL
- Registrable domain (eTLD+1)
- Brand impersonation score
- Typosquatting detection
- Lookalike domain detection
- Fake subdomain detection
- Misleading URL patterns

### Infrastructure Evidence
- Domain age
- Registration information (RDAP/WHOIS)
- DNS records (A, AAAA, MX, NS, TXT)
- IP address
- ASN (Autonomous System Number)
- Hosting provider
- Country
- Nameservers
- TLS certificate
- Certificate age
- Certificate issuer
- Certificate Transparency history
- Related domains (same cert, same IP, same ASN)

### Content Evidence
- Redirect chain
- HTTP status
- Page title
- Page text
- Forms detected
- Password fields
- Phone-number fields
- M-Pesa/payment references
- Payment instructions
- Mobile-money numbers
- WhatsApp links
- Telegram links
- Email addresses
- Social media links
- HTML fingerprint
- DOM fingerprint
- Screenshot hash
- Favicon hash

### Reputation Evidence
- PhishTank match
- OpenPhish match
- URLhaus match
- ThreatFox match
- Spamhaus DROP match
- GreyNoise IP reputation
- Previous Watchtower reports
- First-seen timestamp
- Last-seen timestamp

### Campaign Evidence
- Same payment number across URLs
- Same email across URLs
- Same Telegram handle
- Same WhatsApp number
- Same page fingerprint
- Same analytics ID
- Same JavaScript fingerprints
- Same infrastructure reuse

## Verdict Categories (Not Just 0-100)

- **CONFIRMED_MALICIOUS**: Strong independent evidence exists
- **HIGH_RISK**: Multiple suspicious indicators but insufficient confirmation
- **SUSPICIOUS**: Some concerning indicators
- **LOW_RISK**: Limited evidence of malicious activity
- **VERIFIED_OFFICIAL**: Domain independently validated against authoritative sources
- **UNKNOWN**: Insufficient evidence (Unknown ≠ Safe)

## Scoring Model (Evidence-Based, Not Single Score)

### Identity Risk (0-30 points)
- Brand impersonation: +15-25
- Typosquatting: +20
- Lookalike domain: +15
- Fake subdomain: +10
- Misleading URL: +10

### Infrastructure Risk (0-25 points)
- Newly registered domain (<30 days): +15
- Recently issued certificate (<7 days): +10
- Suspicious ASN: +10
- Free hosting for financial service: +15
- Malicious IP history: +20
- Infrastructure reuse with known scams: +20

### Content Risk (0-30 points)
- Fake login form: +20
- Fake payment form: +25
- Financial credentials requested: +20
- OTP request: +25
- PIN request: +25
- Activation fee mentioned: +20
- Processing fee mentioned: +20
- Fake loan offer: +15
- Fake account upgrade: +15
- Fake reward/prize: +15

### Reputation Risk (0-40 points)
- PhishTank match: +35
- OpenPhish match: +35
- URLhaus match: +30
- ThreatFox match: +30
- Spamhaus DROP match: +40
- Previous Watchtower confirmed reports: +25

### Campaign Risk (0-25 points)
- Related malicious domains: +15
- Same payment number: +20
- Same email: +15
- Same Telegram: +15
- Same WhatsApp: +15
- Same page fingerprint: +20
- Same analytics ID: +10
- Same infrastructure: +15

## Phase 1: Foundation Fixes (Priority: Immediate)

### 1.1 Replace Simple Scoring with Evidence Model
- Create `core/evidence.py` - evidence collection engine
- Create `detection/scoring.py` - multi-factor scoring
- Modify `scamscan.py` to collect evidence, not just keywords

### 1.2 Add Verdict Categories
- Replace numeric-only scores with verdict categories
- Update UI to show verdict badges
- Add explainable evidence display

### 1.3 Integrate Threat Intelligence Feeds
- **PhishTank** (Tier 1 - Phishing intelligence)
- **OpenPhish Community** (Tier 1 - Current phishing URLs)
- **URLhaus** (Tier 2 - Malware URLs)
- **ThreatFox** (Tier 2 - IOCs with confidence)

### 1.4 Improve Certificate Transparency Monitoring
- Dedicated CT pipeline in `hunters/certificate_transparency.py`
- Monitor certificates containing brand names
- Early discovery before blocklists

### 1.5 Add DNS/RDAP/TLS/IP Enrichment
- `enrichment/dns.py` - DNS record collection
- `enrichment/rdap.py` - Domain registration info
- `enrichment/tls.py` - Certificate details
- `enrichment/ip.py` - IP reputation
- `enrichment/asn.py` - ASN/hosting info

### 1.6 Add Analyst Feedback Loop
- Every result gets: Confirm Scam / False Positive / Needs Review
- Store analyst decisions with reasons
- Build proprietary Watchtower dataset

## Phase 2: Smarter Detection

### 2.1 Brand Impersonation Detection
- Expand homoglyph detection
- Add typosquatting algorithms
- Brand token matching in URLs

### 2.2 Payment/Credential/OTP Detection
- Expand artifact patterns
- Detect fake forms
- Identify credential harvesting

### 2.3 HTML/Page Fingerprinting
- Capture page screenshots
- Compute HTML hashes
- DOM fingerprints
- Favicon hashes

### 2.4 Infrastructure Correlation
- Group URLs by shared infrastructure
- Detect campaign patterns
- Map related domains

### 2.5 Campaign Clustering
- Identify scam campaigns
- Link related threats
- Track campaign evolution

## Phase 3: African Advantage

### 3.1 African Financial Brand Database
Expand beyond M-PESA to include:

**Kenya:**
- M-PESA, Safaricom, Fuliza, M-Shwari
- KCB, KCB M-PESA, Equity, Eazzy
- Co-op Bank, NCBA, Loop
- Tala, Branch, Absa, Stanbic, I&M
- Airtel Money, PesaPal, Pesalink
- eCitizen, KRA, NHIF/SHA, HELB

**East Africa:**
- Uganda: MTN MoMo, Airtel Money, Stanbic, Centenary
- Tanzania: M-Pesa, Tigo Pesa, Airtel Money, HaloPesa, CRDB, NMB
- Rwanda: MTN MoMo, Airtel Money, Bank of Kigali

### 3.2 SMS/Smishing Analysis
- Allow SMS submission
- Extract URLs from messages
- Correlate with website intelligence

### 3.3 WhatsApp/Telegram Indicators
- Track scam phone numbers
- Monitor Telegram channels
- Link social infrastructure to websites

### 3.4 Country-Specific Intelligence
- Kenya scam taxonomy
- Tanzanian fraud patterns
- Ugandan mobile money scams
- Regional variations

## Phase 4: Platform Maturation

### 4.1 Architecture Improvements
- Migrate SQLite → PostgreSQL
- Add Redis for queues/caching
- Isolated scanning sandbox
- Worker system for async processing

### 4.2 Threat Graph
- Use graph database for relationships
- Map campaign infrastructure
- Track entity relationships

### 4.3 Campaign Dashboard
- Threats view (individual URLs)
- Campaigns view (grouped threats)
- Infrastructure view (IPs, ASNs, certs)
- Brands view (impersonated organizations)
- Trends view (statistics over time)

### 4.4 Evaluation Framework
Measure:
- Precision (of flagged items, how many are actually malicious)
- Recall (of known malicious, how many detected)
- False Positive Rate
- False Negative Rate
- Time-to-Detection

## Data Sources Priority

| Source | Purpose | Priority |
|--------|---------|----------|
| PhishTank | Confirmed phishing URLs | ⭐⭐⭐⭐⭐ |
| OpenPhish | Current phishing feed | ⭐⭐⭐⭐⭐ |
| URLhaus | Malware distribution URLs | ⭐⭐⭐⭐⭐ |
| ThreatFox | IOCs with confidence | ⭐⭐⭐⭐⭐ |
| Certificate Transparency | New domain discovery | ⭐⭐⭐⭐⭐ |
| Tranco | Legitimate domain baseline | ⭐⭐⭐⭐ |
| Spamhaus DROP | Malicious network ranges | ⭐⭐⭐⭐ |
| GreyNoise | IP reputation | ⭐⭐⭐ |
| Hugging Face datasets | ML training/testing | ⭐⭐⭐⭐ |
| Watchtower analyst feedback | Proprietary labeled data | ⭐⭐⭐⭐⭐ |

## Key Architectural Changes

### Module Structure
```
watchtower/
├── hunters/
│   ├── search_engine.py
│   ├── certificate_transparency.py
│   ├── phishing_feeds.py
│   ├── social_media.py
│   ├── urlhaus.py
│   ├── phishtank.py
│   ├── openphish.py
│   ├── threatfox.py
│   └── infrastructure.py
│
├── enrichment/
│   ├── dns.py
│   ├── rdap.py
│   ├── tls.py
│   ├── ip.py
│   ├── asn.py
│   ├── http.py
│   └── webpage.py
│
├── detection/
│   ├── url_features.py
│   ├── brand_impersonation.py
│   ├── content_analysis.py
│   ├── payment_detection.py
│   ├── credential_detection.py
│   └── scoring.py
│
├── intelligence/
│   ├── phishtank.py
│   ├── urlhaus.py
│   ├── openphish.py
│   ├── threatfox.py
│   └── greynoise.py
│
├── campaigns/
│   ├── clustering.py
│   ├── fingerprints.py
│   └── relationships.py
│
└── core/
    ├── evidence.py       # NEW: evidence collection
    ├── models.py         # EXTENDED: evidence records
    ├── store.py          # EXTENDED: graph storage
    └── ...
```

### Security Considerations

**CRITICAL:** Do not browse suspicious sites from main server
- Use isolated sandbox environment
- Fetch → Extract → Destroy pattern
- Protect scanner from malicious JS, exploits, downloads

## Implementation Order

1. **Week 1-2:** Evidence model, verdict categories, threat intel feeds
2. **Week 3-4:** Enrichment modules, improved scoring, analyst feedback
3. **Week 5-6:** African brand database, campaign detection
4. **Week 7-8:** Infrastructure correlation, fingerprinting
5. **Week 9-10:** Dashboard improvements, evaluation framework
6. **Week 11+:** Architecture migration, graph database, advanced features

## Success Metrics

Instead of "100% accurate", measure:
- Precision rate
- Recall rate  
- False positive rate
- Median time-to-detection
- Campaigns identified
- Unique infrastructure mapped
- Analyst confirmation rate

## The Ultimate Goal

Transform from: **"Find suspicious URLs and score them"**

To: **"Continuously discover, enrich, verify and correlate digital fraud infrastructure across Africa"**

This creates a defensible competitive advantage through:
1. African fraud context expertise
2. Proprietary verified dataset
3. Campaign-level intelligence
4. Explainable verdicts
5. Multi-source correlation
