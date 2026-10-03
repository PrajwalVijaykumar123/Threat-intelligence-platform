# Threat Intelligence Platform (Lightweight)

A Python-based threat intelligence platform that collects real indicators of compromise (IOCs) from open-source threat feeds, stores them in a searchable local database, and allows rapid lookup during incident investigation.

## What This Project Does

- Pulls live, real-world threat data from two legitimate open threat intelligence feeds (abuse.ch):
  - URLhaus - recently identified malicious URLs used for malware distribution
  - Feodo Tracker - known active botnet command-and-control (C2) IP addresses
- Stores all indicators in a local SQLite database with deduplication
- Provides fast search and direct lookup ("is this IP/URL known-malicious?") - the core workflow a SOC analyst uses when triaging logs or alerts
- Tracks indicator source, threat type/malware family, and first-seen date

## Live Data

A real collection run pulled over 16,000 live indicators:

    Total IOCs: 16,198
    By type: url: 16,193 | ip: 5
    By source: URLhaus: 16,193 | Feodo Tracker: 5

A direct lookup against the database correctly identified a real indicator:

    python3 cti_platform.py check 162.243.103.246

    KNOWN MALICIOUS INDICATOR
      Value: 162.243.103.246
      Type: ip
      Source: Feodo Tracker
      Threat type: Emotet
      First seen: 2022-06-04 21:24:53

## Tech Stack

- Python 3.11
- SQLite - local indicator database
- abuse.ch open threat feeds (URLhaus, Feodo Tracker) - no API key required

## Setup

1. Install dependencies:

    python3 -m venv venv
    source venv/bin/activate
    pip install requests

2. Collect the latest threat indicators:

    python3 cti_platform.py collect

3. View database summary:

    python3 cti_platform.py stats

4. Search indicators:

    python3 cti_platform.py search <keyword>

5. Check if a specific IP or URL is known-malicious:

    python3 cti_platform.py check <ip_or_url>

## Architecture

    Open threat feeds (URLhaus, Feodo Tracker)
            |
            v
    Fetch + normalize IOCs
            |
            v
    SQLite database (deduplicated, indexed)
            |
            v
    Search / direct lookup / stats reporting

## What I Learned

- Consuming and normalizing data from real open-source threat intelligence feeds
- Designing a deduplicated, queryable local IOC database
- Building the core analyst workflow of threat intel platforms: collect, enrich, search, and look up during investigation
- Working with live, real-world malicious indicator data (not synthetic test data) safely - the tool only stores and searches indicator metadata, never downloads or executes anything from the flagged URLs

## Next Steps

- Add more feeds (AlienVault OTX, abuse.ch's SSL blacklist, PhishTank)
- Add reputation enrichment via VirusTotal/AbuseIPDB APIs for indicators not already in free feeds
- Scheduled automatic collection (cron job) to keep the database current
- Build a web dashboard consistent with the other projects in this portfolio
- Integrate with the SIEM project - automatically flag log events matching known IOCs
