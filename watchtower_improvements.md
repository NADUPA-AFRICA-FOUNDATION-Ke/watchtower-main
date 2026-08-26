# Watchtower Improvement Plan

Based on comprehensive security research feedback, this document outlines the transformation of Watchtower from a simple scam keyword detector into an evidence-based threat intelligence engine.

## Core Philosophy Change

**From:** "Find suspicious URLs and score them"  
**To:** "Continuously discover, enrich, verify and correlate digital fraud infrastructure across Africa"

## Architecture Overview

```
                         WATCHTOWER
                              │
             ┌────────────────┴────────────────┐
             │                                 │
       DISCOVERY LAYER                   USER SUBMISSIONS
             │                                 │
     ┌───────┼────────┐                        │
     │       │        │                        │
    CT     Search   Threat Feeds               │
     │       │        │                        │
     └───────┼────────┘                        │
             ↓                                 ↓
       URL NORMALIZATION ←──────────────────────┘
             │
             ↓
       ENRICHMENT ENGINE
             │
     ┌───────┼──────────────┐
     │       │              │
    DNS     TLS            IP/ASN
     │       │              │
     └───────┼──────────────┘
             ↓
       CONTENT ANALYSIS
             │
     ┌───────┼──────────────┐
     │       │              │
   Brand   Payment       Credentials
   Match   Detection      Detection
     │       │              │
     └───────┼──────────────┘
             ↓
      THREAT INTELLIGENCE
             │
 ┌───────────┼────────────────────┐
 │           │                    │
PhishTank  OpenPhish          URLhaus
 │           │                    │
ThreatFox  GreyNoise          Spamhaus
 └───────────┼────────────────────┘
             ↓
       EVIDENCE ENGINE
             ↓
       RISK SCORING
             ↓
    ┌────────┼──────────┐
    ↓        ↓          ↓
  SAFE    SUSPICIOUS   MALICIOUS
             │
             ↓
       CAMPAIGN ENGINE
             ↓
       WATCHTOWER GRAPH
             ↓
          DASHBOARD
```

## Phase 1: Fix the Foundation (Priority: CRITICAL)

### 1.1 Replace Simple Scoring with Evidence-Based Model

**Current:** `suspicious keyword + suspicious domain + suspicious hosting = scam`

**New:** Multi-factor evidence collection with correlation

Evidence categories to collect for every URL:
- Domain information (age, registration, DNS records)
- Infrastructure (IP, ASN, hosting provider, country, nameservers)
- TLS certificate (age, issuer, CT history)
- Content analysis (title, text, forms, payment fields)
- Artifacts (phone numbers, WhatsApp, Telegram, email, payment instructions)
- Brand impersonation signals
- External threat intelligence matches
- Campaign relationships

### 1.2 Implement Proper Verdict Categories

Replace numeric scores with confidence-based verdicts:
- `CONFIRMED_MALICIOUS` - Strong independent evidence
- `HIGH_RISK` - Multiple suspicious indicators
- `SUSPICIOUS` - Some concerning indicators
- `LOW_RISK` - Limited evidence of malicious activity
- `VERIFIED_OFFICIAL` - Independently validated
- `UNKNOWN` - Insufficient evidence (important: Unknown ≠ Safe)

### 1.3 Add Explainable Evidence

Instead of "Risk: 93/100", show:
```
Risk: 93/100 — HIGH RISK

+30 Brand impersonation
+20 Newly registered domain
+15 Suspicious payment language
+15 Credential collection
+10 Related malicious infrastructure
+10 External threat intelligence match

Why Watchtower flagged this: [explanation]
```

### 1.4 Integrate Threat Intelligence Feeds

Priority sources:
1. **PhishTank** (Tier 1) - Confirmed phishing URLs
2. **OpenPhish Community** (Tier 1) - Current phishing URLs
3. **URLhaus** (Tier 1) - Malware-associated URLs
4. **ThreatFox** (Tier 1) - Domains, IPs, IOCs with threat types
5. **Certificate Transparency** (Tier 1) - Early discovery
6. **Tranco** (Tier 2) - Legitimate domain baseline
7. **Spamhaus DROP** (Tier 2) - Malicious network ranges
8. **GreyNoise Community** (Tier 3) - IP reputation

**Critical:** Treat all external data as EVIDENCE, not TRUTH. Never let one signal decide the verdict.

### 1.5 Add Analyst Feedback Loop

Every result should support:
- Confirm Scam
- False Positive
- Needs Review

Store: URL, verdict, analyst, reason, timestamp, evidence, source

This creates Watchtower's proprietary labeled dataset.

## Phase 2: Make Detection Smarter

### 2.1 Brand Impersonation Detection

African financial brands to monitor:
- **Kenya:** M-PESA, Safaricom, Fuliza, M-Shwari, KCB, Equity, Co-op Bank, NCBA, Tala, Branch, Airtel Money, PesaPal, Pesalink, eCitizen, KRA, NHIF, HELB
- **East Africa:** MTN Mobile Money, Tigo Pesa, HaloPesa, CRDB, NMB, Bank of Kigali
- **Expansion:** Nigeria, Ghana, Zambia, Malawi, South Africa

### 2.2 Infrastructure Intelligence

Track relationships:
```
Domain → IP → ASN → Hosting → Certificate → Related domains
```

Look for infrastructure reuse across campaigns.

### 2.3 Page Fingerprinting

For each suspicious site capture:
- Screenshot
- HTML hash
- DOM fingerprint
- Text fingerprint
- Favicon hash
- Forms detected
- External resources

Enable campaign template recognition.

### 2.4 Campaign Clustering

Group related threats by:
- Same payment number
- Same email/WhatsApp/Telegram
- Same page fingerprint
- Same analytics ID
- Same infrastructure
- Similar URL patterns

## Phase 3: Build African Advantage

### 3.1 Create African Fraud Dataset

Schema:
```
URL, domain, country, brand, service, scam_type, language, platform,
hosting, ASN, IP, registration_date, first_seen, last_seen,
certificate_age, payment_number, whatsapp, telegram, email,
credential_collection, OTP_request, PIN_request, activation_fee,
processing_fee, loan_scam, investment_scam, job_scam,
government_impersonation, confirmed_label, confidence, source,
analyst_verification
```

### 3.2 SMS/WhatsApp Scam Intelligence

Allow users to submit scam messages. Extract:
- URL
- Brand
- Phone number
- Amount/currency
- Language
- Urgency indicators
- Financial claims
- Payment requests
- Social engineering indicators

### 3.3 African Language Support

Detect scams in:
- English
- Swahili
- Local languages

## Phase 4: Platform Hardening

### 4.1 Isolated Scanning Environment

**CRITICAL SECURITY:** Do not browse suspicious sites from main server.

Implement sandboxed scanning:
```
Internet → Discovery Worker → Sandbox → Browser/HTTP fetch → Extract → Destroy
```

### 4.2 Database Migration Path

SQLite is fine for MVP, but design for PostgreSQL:
- PostgreSQL: structured intelligence
- Redis: queues/caching/rate limiting
- Object storage: HTML snapshots/screenshots
- Worker system: async OSINT scans

### 4.3 Modular Architecture

Reorganize code:
```
watchtower/
├── hunters/          # Discovery sources
│   ├── search_engine.py
│   ├── certificate_transparency.py
│   ├── phishtank.py
│   ├── urlhaus.py
│   ├── openphish.py
│   └── threatfox.py
├── enrichment/       # Data gathering
│   ├── dns.py
│   ├── rdap.py
│   ├── tls.py
│   ├── ip.py
│   └── webpage.py
├── detection/        # Analysis
│   ├── brand_impersonation.py
│   ├── content_analysis.py
│   ├── payment_detection.py
│   └── scoring.py
├── intelligence/     # External feeds
│   ├── phishtank.py
│   ├── urlhaus.py
│   └── greynoise.py
└── campaigns/        # Correlation
    ├── clustering.py
    └── fingerprints.py
```

## Metrics That Matter

Stop claiming "100% accurate". Measure:

- **Precision:** Of everything flagged malicious, how much is actually malicious?
- **Recall:** Of known malicious URLs, how many does Watchtower detect?
- **False Positive Rate:** How often are legitimate sites incorrectly flagged?
- **False Negative Rate:** How many known scams slip through?
- **Time-to-Detection:** How long after appearance does Watchtower discover it?

Example meaningful metric:
> Median time to detect newly observed phishing infrastructure: 18 minutes

## Implementation Priorities

### Immediate (Week 1-2)
1. Remove "100% accurate" claims
2. Implement evidence-based scoring
3. Add proper verdict categories
4. Integrate PhishTank
5. Add OpenPhish
6. Add URLhaus
7. Add ThreatFox
8. Improve CT monitoring
9. Add DNS/RDAP/TLS/IP enrichment
10. Add analyst feedback

### Short-term (Month 1)
11. Brand impersonation detection
12. Typosquatting detection
13. Payment/credential/OTP detection
14. HTML/page fingerprinting
15. Screenshot capture
16. Redirect-chain analysis
17. Infrastructure correlation
18. Campaign clustering

### Medium-term (Quarter 1)
19. African financial brand database
20. Kenyan scam taxonomy
21. SMS/smishing analysis
22. WhatsApp/Telegram indicators
23. African-language scam detection
24. Country-specific intelligence
25. Watchtower's own verified dataset

### Long-term (Quarter 2+)
26. PostgreSQL migration
27. Redis/worker architecture
28. Isolated scanning sandbox
29. Threat graph database
30. Campaign dashboard
31. Analyst console
32. External API
33. Automated alerts
34. Continuous model evaluation

## Key Design Principles

1. **Evidence over assertion:** Collect multiple independent signals
2. **Correlation over single indicators:** Infrastructure reuse reveals campaigns
3. **Explainability over opacity:** Show why something was flagged
4. **Feedback over static models:** Learn from analyst confirmations
5. **African focus over generic:** Specialize in African financial fraud
6. **Safety over convenience:** Sandboxed scanning, fail-closed authentication
7. **Intelligence over blocklists:** Understand infrastructure, don't just list URLs
