import asyncio
import uuid
from datetime import datetime

from services.ioc_detector import detect_type
from services.otx_service import query_otx
from services.abusech_service import query_urlhaus, query_malwarebazaar
from services.geo_service import query_geo
from services.whois_service import query_whois
from services import ml_service
from utils.severity import compute_score, score_to_severity, generate_recommendations


async def run_scan(ioc_value: str) -> dict:
    """Run a full threat intelligence scan against all feeds.

    Returns a dict matching the ScanResponse shape.
    """
    ioc_value = ioc_value.strip()
    ioc_type = detect_type(ioc_value)
    scan_id = str(uuid.uuid4())
    scanned_at = datetime.utcnow()

    # ---- Fan out concurrent feed queries ----
    otx_task = query_otx(ioc_value, ioc_type)
    urlhaus_task = query_urlhaus(ioc_value, ioc_type)
    malwarebazaar_task = query_malwarebazaar(ioc_value, ioc_type)

    tasks = [otx_task, urlhaus_task, malwarebazaar_task]

    # Geo / WHOIS run concurrently but are type-specific
    geo_future = None
    whois_future = None

    if ioc_type == "ip":
        geo_future = query_geo(ioc_value)
    elif ioc_type == "domain":
        # Run whois in a thread executor to avoid blocking the event loop
        loop = asyncio.get_event_loop()
        whois_future = loop.run_in_executor(None, query_whois, ioc_value)

    # Gather feed results
    otx_result, urlhaus_result, malwarebazaar_result = await asyncio.gather(*tasks)

    geo_result = None
    whois_result = None

    if geo_future is not None:
        try:
            geo_result = await geo_future
        except Exception:
            geo_result = None

    if whois_future is not None:
        try:
            whois_result = await whois_future
        except Exception:
            whois_result = None

    # ---- Build feeds dict ----
    feed_results = {
        "otx": otx_result,
        "urlhaus": urlhaus_result,
        "malwarebazaar": malwarebazaar_result,
    }

    # ---- Compute threat score and severity ----
    threat_score = compute_score(feed_results)
    overall_severity = score_to_severity(threat_score)

    # ---- ML prediction ----
    scan_data_for_ml = {
        "ioc_type": ioc_type,
        "threat_score": threat_score,
        "feeds": feed_results,
    }
    ml_result = ml_service.predict_severity(scan_data_for_ml)
    ml_severity = ml_result.get("ml_severity")
    ml_confidence = ml_result.get("ml_confidence")

    # ---- Blacklist status ----
    blacklist_status = {
        "otx": otx_result.get("found", False),
        "urlhaus": urlhaus_result.get("found", False),
        "malwarebazaar": malwarebazaar_result.get("found", False),
        "listed_on": [],
    }
    listed = []
    if otx_result.get("found"):
        listed.append("OTX")
    if urlhaus_result.get("found"):
        listed.append("URLhaus")
    if malwarebazaar_result.get("found"):
        listed.append("MalwareBazaar")
    blacklist_status["listed_on"] = listed

    # ---- Recommendations ----
    recommendations = generate_recommendations(overall_severity, feed_results)

    # ---- IoC dict ----
    ioc_dict = {
        "value": ioc_value,
        "type": ioc_type,
    }
    if geo_result:
        ioc_dict["geo"] = geo_result
    if whois_result:
        ioc_dict["whois"] = whois_result

    return {
        "scan_id": scan_id,
        "ioc": ioc_dict,
        "ioc_value": ioc_value,
        "ioc_type": ioc_type,
        "overall_severity": overall_severity,
        "threat_score": threat_score,
        "ml_severity": ml_severity,
        "ml_confidence": ml_confidence,
        "scanned_at": scanned_at,
        "feeds": feed_results,
        "blacklist_status": blacklist_status,
        "recommendations": recommendations,
    }
