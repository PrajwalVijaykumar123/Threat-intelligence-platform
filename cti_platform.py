"""
Lightweight Threat Intelligence Platform
Pulls IOCs (Indicators of Compromise) from free public threat feeds,
enriches them with reputation data, and stores them in a searchable
local SQLite database.

Feeds used:
- URLhaus (abuse.ch) - malicious URLs, free, no API key required
- Feodo Tracker (abuse.ch) - known botnet C2 IP addresses, free, no API key required

Both are legitimate, widely-used open threat intelligence feeds maintained
by abuse.ch, a Swiss nonprofit cybersecurity project.
"""

import sqlite3
import json
import sys
from datetime import datetime

import requests

DB_PATH = "threat_intel.db"

URLHAUS_FEED = "https://urlhaus.abuse.ch/downloads/json_recent/"
FEODO_FEED = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_type TEXT,
            ioc_value TEXT UNIQUE,
            source TEXT,
            threat_type TEXT,
            first_seen TEXT,
            added_at TEXT,
            raw_data TEXT
        )
    """)
    conn.commit()
    conn.close()


def fetch_urlhaus():
    print("Fetching malicious URLs from URLhaus...")
    try:
        resp = requests.get(URLHAUS_FEED, timeout=20)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"  Error fetching URLhaus feed: {e}")
        return []

    iocs = []
    for entry_list in data.values():
        entry = entry_list[0] if isinstance(entry_list, list) else entry_list
        iocs.append({
            "ioc_type": "url",
            "ioc_value": entry.get("url", ""),
            "source": "URLhaus",
            "threat_type": entry.get("threat", "malware_download"),
            "first_seen": entry.get("dateadded", ""),
            "raw_data": json.dumps(entry),
        })
    print(f"  Retrieved {len(iocs)} URL indicators.")
    return iocs


def fetch_feodo():
    print("Fetching botnet C2 IPs from Feodo Tracker...")
    try:
        resp = requests.get(FEODO_FEED, timeout=20)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"  Error fetching Feodo Tracker feed: {e}")
        return []

    iocs = []
    for entry in data:
        iocs.append({
            "ioc_type": "ip",
            "ioc_value": entry.get("ip_address", ""),
            "source": "Feodo Tracker",
            "threat_type": entry.get("malware", "botnet_c2"),
            "first_seen": entry.get("first_seen", ""),
            "raw_data": json.dumps(entry),
        })
    print(f"  Retrieved {len(iocs)} IP indicators.")
    return iocs


def store_iocs(iocs):
    conn = sqlite3.connect(DB_PATH)
    new_count = 0
    for ioc in iocs:
        try:
            conn.execute("""
                INSERT OR IGNORE INTO iocs
                (ioc_type, ioc_value, source, threat_type, first_seen, added_at, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                ioc["ioc_type"], ioc["ioc_value"], ioc["source"],
                ioc["threat_type"], ioc["first_seen"],
                datetime.now().isoformat(), ioc["raw_data"]
            ))
            if conn.total_changes:
                new_count += 1
        except sqlite3.Error as e:
            print(f"  DB error on {ioc['ioc_value']}: {e}")
    conn.commit()
    conn.close()
    return new_count


def collect_all_feeds():
    init_db()
    all_iocs = []
    all_iocs.extend(fetch_urlhaus())
    all_iocs.extend(fetch_feodo())

    new_count = store_iocs(all_iocs)
    print(f"\nCollection complete. {new_count} new indicator(s) added to database.")
    return new_count


def search_iocs(query=None, ioc_type=None, source=None, limit=50):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    sql = "SELECT * FROM iocs WHERE 1=1"
    params = []

    if query:
        sql += " AND ioc_value LIKE ?"
        params.append(f"%{query}%")
    if ioc_type:
        sql += " AND ioc_type = ?"
        params.append(ioc_type)
    if source:
        sql += " AND source = ?"
        params.append(source)

    sql += " ORDER BY added_at DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_stats():
    conn = sqlite3.connect(DB_PATH)
    total = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    by_type = conn.execute("SELECT ioc_type, COUNT(*) FROM iocs GROUP BY ioc_type").fetchall()
    by_source = conn.execute("SELECT source, COUNT(*) FROM iocs GROUP BY source").fetchall()
    conn.close()
    return {
        "total_iocs": total,
        "by_type": dict(by_type),
        "by_source": dict(by_source),
    }


def check_ioc(value):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM iocs WHERE ioc_value = ?", (value,)).fetchone()
    conn.close()
    return dict(row) if row else None


def print_stats():
    stats = get_stats()
    print(f"\n{'=' * 50}")
    print(f"Threat Intelligence Database Summary")
    print(f"{'=' * 50}")
    print(f"Total IOCs: {stats['total_iocs']}")
    print(f"\nBy type:")
    for t, count in stats["by_type"].items():
        print(f"  {t}: {count}")
    print(f"\nBy source:")
    for s, count in stats["by_source"].items():
        print(f"  {s}: {count}")
    print(f"{'=' * 50}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 cti_platform.py collect              # Pull latest IOCs from feeds")
        print("  python3 cti_platform.py stats                # Show database summary")
        print("  python3 cti_platform.py search <query>       # Search IOCs")
        print("  python3 cti_platform.py check <value>        # Check if a specific IP/URL is known-malicious")
        sys.exit(1)

    command = sys.argv[1]

    if command == "collect":
        collect_all_feeds()
        print_stats()

    elif command == "stats":
        print_stats()

    elif command == "search":
        query = sys.argv[2] if len(sys.argv) > 2 else None
        results = search_iocs(query=query)
        print(f"\nFound {len(results)} result(s):\n")
        for r in results:
            print(f"  [{r['ioc_type'].upper()}] {r['ioc_value']}")
            print(f"    Source: {r['source']} | Threat: {r['threat_type']} | First seen: {r['first_seen']}")
            print()

    elif command == "check":
        if len(sys.argv) < 3:
            print("Usage: python3 cti_platform.py check <ip_or_url>")
            sys.exit(1)
        value = sys.argv[2]
        result = check_ioc(value)
        if result:
            print(f"\n⚠ KNOWN MALICIOUS INDICATOR")
            print(f"  Value: {result['ioc_value']}")
            print(f"  Type: {result['ioc_type']}")
            print(f"  Source: {result['source']}")
            print(f"  Threat type: {result['threat_type']}")
            print(f"  First seen: {result['first_seen']}\n")
        else:
            print(f"\n'{value}' not found in local threat intelligence database.\n")

    else:
        print(f"Unknown command: {command}")
