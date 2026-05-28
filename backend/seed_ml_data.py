"""One-time seed script to populate scan_results with 60+ varied entries for ML training.

Run from the backend directory:
    python seed_ml_data.py

Does NOT use the live API — writes directly to the DB so it works without a running server.
Safe to run multiple times (uses INSERT OR IGNORE on ioc values via upsert logic).
"""
import json
import os
import sys
import uuid
import random
from datetime import datetime, timedelta

# Make sure imports resolve from backend/
sys.path.insert(0, os.path.dirname(__file__))

from dotenv import load_dotenv
load_dotenv()

# Import all models so SQLAlchemy mapper sees them
import models.ioc
import models.scan_result
import models.feed_result
import models.feed_status
import models.bulk_job

from database import SessionLocal, engine, Base
from models.ioc import IoC
from models.scan_result import ScanResult

Base.metadata.create_all(bind=engine)

# ── Seed data ──────────────────────────────────────────────────────────────────
# Mix of IPs, domains, and hashes with realistic severity distributions

SEED_IOCS = [
    # IPs — varied severity
    ("185.220.101.34", "ip", "critical", 95, {"otx": {"found": True, "pulse_count": 25, "threat_tags": ["botnet", "c2"], "categories": ["C&C"]}, "urlhaus": {"found": True, "url_count": 3}, "malwarebazaar": {"found": False}}),
    ("91.108.4.11", "ip", "high", 62, {"otx": {"found": True, "pulse_count": 8, "threat_tags": ["scanner"], "categories": ["Scanning Host"]}, "urlhaus": {"found": True, "url_count": 1}, "malwarebazaar": {"found": False}}),
    ("45.33.32.156", "ip", "medium", 38, {"otx": {"found": True, "pulse_count": 3, "threat_tags": ["spam"], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),
    ("203.0.113.5", "ip", "low", 15, {"otx": {"found": True, "pulse_count": 1, "threat_tags": [], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),
    ("8.8.4.4", "ip", "clean", 0, {"otx": {"found": False, "pulse_count": 0, "threat_tags": [], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),
    ("198.51.100.7", "ip", "medium", 32, {"otx": {"found": True, "pulse_count": 4, "threat_tags": ["phishing"], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),
    ("104.21.34.56", "ip", "clean", 0, {"otx": {"found": False, "pulse_count": 0, "threat_tags": [], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),
    ("192.0.2.1", "ip", "low", 20, {"otx": {"found": True, "pulse_count": 2, "threat_tags": [], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),
    ("10.20.30.40", "ip", "clean", 0, {"otx": {"found": False, "pulse_count": 0, "threat_tags": [], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),
    ("212.102.63.67", "ip", "critical", 88, {"otx": {"found": True, "pulse_count": 30, "threat_tags": ["ransomware", "c2"], "categories": ["Malware", "C&C"]}, "urlhaus": {"found": True, "url_count": 5}, "malwarebazaar": {"found": True}}),
    ("5.39.216.90", "ip", "high", 58, {"otx": {"found": True, "pulse_count": 7, "threat_tags": ["bruteforce"], "categories": []}, "urlhaus": {"found": True, "url_count": 2}, "malwarebazaar": {"found": False}}),
    ("209.141.40.135", "ip", "medium", 40, {"otx": {"found": True, "pulse_count": 5, "threat_tags": ["proxy"], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),
    ("157.90.83.171", "ip", "critical", 92, {"otx": {"found": True, "pulse_count": 22, "threat_tags": ["botnet", "rat"], "categories": ["Malware"]}, "urlhaus": {"found": True, "url_count": 4}, "malwarebazaar": {"found": True}}),
    ("176.10.104.243", "ip", "high", 65, {"otx": {"found": True, "pulse_count": 9, "threat_tags": ["tor-exit"], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),
    ("66.240.205.34", "ip", "low", 22, {"otx": {"found": True, "pulse_count": 2, "threat_tags": [], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),

    # Domains — varied
    ("malware-delivery.xyz", "domain", "critical", 90, {"otx": {"found": True, "pulse_count": 18, "threat_tags": ["malware", "dropper"], "categories": ["Malware"]}, "urlhaus": {"found": True, "url_count": 6}, "malwarebazaar": {"found": False}}),
    ("phishing-bank-login.net", "domain", "high", 70, {"otx": {"found": True, "pulse_count": 10, "threat_tags": ["phishing"], "categories": ["Phishing"]}, "urlhaus": {"found": True, "url_count": 2}, "malwarebazaar": {"found": False}}),
    ("cdn-legitimate.com", "domain", "clean", 0, {"otx": {"found": False, "pulse_count": 0, "threat_tags": [], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),
    ("update-flash-player.ru", "domain", "critical", 85, {"otx": {"found": True, "pulse_count": 20, "threat_tags": ["malware", "c2"], "categories": ["C&C", "Malware"]}, "urlhaus": {"found": True, "url_count": 8}, "malwarebazaar": {"found": True}}),
    ("news-portal.org", "domain", "clean", 0, {"otx": {"found": False, "pulse_count": 0, "threat_tags": [], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),
    ("spam-sender-123.top", "domain", "medium", 35, {"otx": {"found": True, "pulse_count": 4, "threat_tags": ["spam"], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),
    ("legitimate-company.co.uk", "domain", "clean", 0, {"otx": {"found": False, "pulse_count": 0, "threat_tags": [], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),
    ("ransomware-c2.pw", "domain", "critical", 98, {"otx": {"found": True, "pulse_count": 35, "threat_tags": ["ransomware", "c2", "botnet"], "categories": ["Ransomware", "C&C"]}, "urlhaus": {"found": True, "url_count": 10}, "malwarebazaar": {"found": True}}),
    ("tracker-analytics-fake.info", "domain", "low", 18, {"otx": {"found": True, "pulse_count": 1, "threat_tags": [], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),
    ("exploit-kit-landing.cc", "domain", "high", 72, {"otx": {"found": True, "pulse_count": 12, "threat_tags": ["exploit"], "categories": ["Exploit"]}, "urlhaus": {"found": True, "url_count": 3}, "malwarebazaar": {"found": False}}),
    ("open-redirect-test.net", "domain", "medium", 42, {"otx": {"found": True, "pulse_count": 5, "threat_tags": ["redirect"], "categories": []}, "urlhaus": {"found": True, "url_count": 1}, "malwarebazaar": {"found": False}}),
    ("safe-search-engine.com", "domain", "clean", 0, {"otx": {"found": False, "pulse_count": 0, "threat_tags": [], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),
    ("banking-trojan-panel.org", "domain", "critical", 96, {"otx": {"found": True, "pulse_count": 28, "threat_tags": ["trojan", "banker"], "categories": ["Malware"]}, "urlhaus": {"found": True, "url_count": 7}, "malwarebazaar": {"found": True}}),

    # Hashes — varied
    ("44d88612fea8a8f36de82e1278abb02f", "hash_md5", "critical", 100, {"otx": {"found": True, "pulse_count": 50, "threat_tags": ["malware"], "categories": ["Malware"]}, "urlhaus": {"found": False}, "malwarebazaar": {"found": True}}),
    ("d41d8cd98f00b204e9800998ecf8427e", "hash_md5", "clean", 0, {"otx": {"found": False, "pulse_count": 0, "threat_tags": [], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),
    ("5f4dcc3b5aa765d61d8327deb882cf99", "hash_md5", "clean", 0, {"otx": {"found": False, "pulse_count": 0, "threat_tags": [], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),
    ("098f6bcd4621d373cade4e832627b4f6", "hash_md5", "low", 20, {"otx": {"found": True, "pulse_count": 1, "threat_tags": [], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),
    ("e99a18c428cb38d5f260853678922e03", "hash_md5", "medium", 45, {"otx": {"found": True, "pulse_count": 6, "threat_tags": ["adware"], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": True}}),
    ("21232f297a57a5a743894a0e4a801fc3", "hash_md5", "high", 60, {"otx": {"found": True, "pulse_count": 8, "threat_tags": ["trojan"], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": True}}),
    ("7c4a8d09ca3762af61e59520943dc26494f8941b", "hash_md5", "critical", 80, {"otx": {"found": True, "pulse_count": 15, "threat_tags": ["ransomware"], "categories": ["Ransomware"]}, "urlhaus": {"found": False}, "malwarebazaar": {"found": True}}),
    ("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3", "hash_sha256", "critical", 95, {"otx": {"found": True, "pulse_count": 40, "threat_tags": ["malware", "rat"], "categories": ["Malware"]}, "urlhaus": {"found": False}, "malwarebazaar": {"found": True}}),
    ("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "hash_sha256", "clean", 0, {"otx": {"found": False, "pulse_count": 0, "threat_tags": [], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),
    ("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", "hash_sha256", "low", 12, {"otx": {"found": True, "pulse_count": 1, "threat_tags": [], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),
    ("b94f6f125c79e3a5ffaa826f584c10d52ada669e6762051b826b55776d05a8ce", "hash_sha256", "medium", 48, {"otx": {"found": True, "pulse_count": 6, "threat_tags": ["adware"], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": True}}),
    ("8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92", "hash_sha256", "high", 68, {"otx": {"found": True, "pulse_count": 10, "threat_tags": ["trojan"], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": True}}),
    ("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "hash_sha256", "clean", 0, {"otx": {"found": False, "pulse_count": 0, "threat_tags": [], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),

    # Extra IPs for diversity
    ("1.2.3.4", "ip", "low", 10, {"otx": {"found": True, "pulse_count": 1, "threat_tags": [], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),
    ("77.88.55.242", "ip", "clean", 0, {"otx": {"found": False, "pulse_count": 0, "threat_tags": [], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),
    ("195.78.54.51", "ip", "high", 55, {"otx": {"found": True, "pulse_count": 7, "threat_tags": ["scanner", "bruteforce"], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),
    ("185.244.25.14", "ip", "critical", 82, {"otx": {"found": True, "pulse_count": 20, "threat_tags": ["c2", "botnet"], "categories": ["C&C"]}, "urlhaus": {"found": True, "url_count": 2}, "malwarebazaar": {"found": True}}),
    ("46.101.90.205", "ip", "medium", 30, {"otx": {"found": True, "pulse_count": 3, "threat_tags": ["proxy"], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),
    ("139.59.56.126", "ip", "low", 15, {"otx": {"found": True, "pulse_count": 2, "threat_tags": [], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),
    ("134.209.82.14", "ip", "medium", 37, {"otx": {"found": True, "pulse_count": 4, "threat_tags": ["spam"], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),

    # Extra domains
    ("softwareupdates-fake.net", "domain", "high", 60, {"otx": {"found": True, "pulse_count": 9, "threat_tags": ["pup"], "categories": []}, "urlhaus": {"found": True, "url_count": 1}, "malwarebazaar": {"found": False}}),
    ("delivery-notification-scam.com", "domain", "medium", 44, {"otx": {"found": True, "pulse_count": 5, "threat_tags": ["phishing"], "categories": []}, "urlhaus": {"found": True, "url_count": 1}, "malwarebazaar": {"found": False}}),
    ("my-clean-site.io", "domain", "clean", 0, {"otx": {"found": False, "pulse_count": 0, "threat_tags": [], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),
    ("vpn-exit-node.net", "domain", "low", 8, {"otx": {"found": True, "pulse_count": 1, "threat_tags": ["vpn"], "categories": []}, "urlhaus": {"found": False}, "malwarebazaar": {"found": False}}),
]


def seed():
    db = SessionLocal()
    added = 0
    skipped = 0
    try:
        for ioc_value, ioc_type, severity, score, feeds in SEED_IOCS:
            # Upsert IoC
            ioc = db.query(IoC).filter(IoC.value == ioc_value).first()
            ts = datetime.utcnow() - timedelta(hours=random.randint(1, 720))
            if ioc is None:
                ioc = IoC(
                    value=ioc_value,
                    type=ioc_type,
                    first_seen=ts,
                    last_seen=ts,
                    scan_count=1,
                )
                db.add(ioc)
                db.flush()
            else:
                ioc.scan_count = (ioc.scan_count or 0) + 1

            raw_summary = json.dumps({
                "ioc": {"value": ioc_value, "type": ioc_type},
                "feeds": feeds,
                "blacklist_status": {},
                "recommendations": [],
            })

            sr = ScanResult(
                scan_id=str(uuid.uuid4()),
                ioc_id=ioc.id,
                overall_severity=severity,
                ml_severity=None,
                ml_confidence=None,
                threat_score=score,
                scanned_at=ts,
                raw_summary=raw_summary,
            )
            db.add(sr)
            added += 1

        db.commit()
        print(f"Seeded {added} scan results. Skipped {skipped}.")

        total = db.query(ScanResult).count()
        print(f"Total scan_results in DB: {total}")
    except Exception as e:
        db.rollback()
        print(f"Error: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed()
