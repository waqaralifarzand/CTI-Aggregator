"""Seed the database with sample data for development and demos."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timezone, timedelta
import random
import json

from backend.database import init_db, SessionLocal
from backend.models.indicator import Indicator


SAMPLE_IPS = ["185.220.101.45", "45.33.32.156", "91.219.236.174", "198.51.100.1", "203.0.113.42"]
SAMPLE_DOMAINS = ["evil-domain.com", "malware-c2.net", "phishing-site.org", "bad-actor.info", "exploit-kit.xyz"]
SAMPLE_URLS = [
    "http://malware-c2.net/payload.exe",
    "https://phishing-site.org/login.html",
    "http://exploit-kit.xyz/gate.php",
]
SAMPLE_HASHES = [
    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "deadbeef" * 8,
    "cafebabe" * 8,
]
SAMPLE_FAMILIES = ["Emotet", "Mirai", "AgentTesla", "QakBot", "Dridex", None, None]
FEEDS = ["urlhaus", "malwarebazaar", "alienvault_otx", "misp"]
SEVERITIES = ["low", "medium", "high", "critical"]


def seed():
    init_db()
    db = SessionLocal()

    try:
        count = 0
        now = datetime.now(tz=timezone.utc)

        # IP indicators
        for ip in SAMPLE_IPS:
            for feed in random.sample(FEEDS, k=random.randint(1, 3)):
                days_ago = random.randint(1, 90)
                db.add(Indicator(
                    ioc_value=ip,
                    ioc_type="ip",
                    source_feed=feed,
                    first_seen=now - timedelta(days=days_ago),
                    last_seen=now - timedelta(days=random.randint(0, days_ago)),
                    severity=random.choice(SEVERITIES),
                    confidence=random.uniform(40, 95),
                    tags=json.dumps(random.sample(["botnet", "c2", "tor", "scan", "brute-force"], k=2)),
                    malware_family=random.choice(SAMPLE_FAMILIES),
                    tlp=random.choice(["white", "green", "amber"]),
                ))
                count += 1

        # Domain indicators
        for domain in SAMPLE_DOMAINS:
            for feed in random.sample(FEEDS, k=random.randint(1, 2)):
                days_ago = random.randint(1, 60)
                db.add(Indicator(
                    ioc_value=domain,
                    ioc_type="domain",
                    source_feed=feed,
                    first_seen=now - timedelta(days=days_ago),
                    last_seen=now - timedelta(days=random.randint(0, days_ago)),
                    severity=random.choice(["medium", "high", "critical"]),
                    confidence=random.uniform(50, 90),
                    tags=json.dumps(["phishing", "malware"]),
                    malware_family=random.choice(SAMPLE_FAMILIES),
                    tlp="white",
                ))
                count += 1

        # URL indicators
        for url in SAMPLE_URLS:
            db.add(Indicator(
                ioc_value=url,
                ioc_type="url",
                source_feed="urlhaus",
                first_seen=now - timedelta(days=random.randint(1, 30)),
                severity="high",
                confidence=80.0,
                tags=json.dumps(["malware_download"]),
                malware_family=random.choice(SAMPLE_FAMILIES),
                tlp="white",
            ))
            count += 1

        # Hash indicators
        for h in SAMPLE_HASHES:
            db.add(Indicator(
                ioc_value=h,
                ioc_type="hash_sha256",
                source_feed="malwarebazaar",
                first_seen=now - timedelta(days=random.randint(1, 45)),
                severity=random.choice(["high", "critical"]),
                confidence=90.0,
                tags=json.dumps(["trojan"]),
                malware_family=random.choice(["AgentTesla", "Emotet", "QakBot"]),
                tlp="white",
            ))
            count += 1

        db.commit()
        print(f"Seeded {count} indicators into database.")

    finally:
        db.close()


if __name__ == "__main__":
    seed()
