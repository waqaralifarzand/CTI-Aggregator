HIGH_RISK_OTX_TAGS = {"c2", "botnet", "ransomware", "rat"}


def compute_score(feed_results: dict) -> int:
    score = 0
    otx = feed_results.get("otx", {}) or {}
    urlhaus = feed_results.get("urlhaus", {}) or {}
    malwarebazaar = feed_results.get("malwarebazaar", {}) or {}
    vt = feed_results.get("virustotal", {}) or {}

    # OTX scoring
    if otx.get("found"):
        score += 20
        pulse_count = otx.get("pulse_count", 0) or 0
        if pulse_count > 20:
            score += 25
        elif pulse_count > 5:
            score += 15
        tags = {t.lower() for t in (otx.get("threat_tags") or [])}
        if tags & HIGH_RISK_OTX_TAGS:
            score += 15

    # URLhaus scoring
    uh_found = urlhaus.get("found", False)
    if uh_found:
        score += 30

    # MalwareBazaar scoring
    mb_found = malwarebazaar.get("found", False)
    if mb_found:
        score += 35

    # Combo bonus
    if uh_found and mb_found:
        score += 10

    # VirusTotal scoring
    vt_detections = vt.get("detections", 0) or 0
    if vt_detections > 30:
        score += 40
    elif vt_detections > 10:
        score += 30
    elif vt_detections > 0:
        score += 20

    return min(score, 100)


def score_to_severity(score: int) -> str:
    if score == 0:
        return "clean"
    if score <= 25:
        return "low"
    if score <= 50:
        return "medium"
    if score <= 75:
        return "high"
    return "critical"


def generate_recommendations(severity: str, feed_results: dict) -> list:
    recs = []
    otx = feed_results.get("otx", {}) or {}
    urlhaus = feed_results.get("urlhaus", {}) or {}
    malwarebazaar = feed_results.get("malwarebazaar", {}) or {}
    vt = feed_results.get("virustotal", {}) or {}

    if malwarebazaar.get("found"):
        sig = malwarebazaar.get("signature", "unknown malware")
        recs.append(f"Hash confirmed in MalwareBazaar as {sig}. Quarantine the file immediately and perform forensic analysis on affected systems.")

    if urlhaus.get("found"):
        recs.append("Host flagged in URLhaus as a malware distribution point. Block at perimeter firewall and DNS sinkholes immediately.")

    if otx.get("found"):
        pulse_count = otx.get("pulse_count", 0) or 0
        tags = otx.get("threat_tags") or []
        high_tags = [t for t in tags if t.lower() in HIGH_RISK_OTX_TAGS]
        if high_tags:
            recs.append(f"OTX intelligence links this IoC to {', '.join(high_tags)} activity across {pulse_count} pulse(s). Treat as active threat.")
        else:
            recs.append(f"Found in {pulse_count} OTX pulse(s). Review pulse details for threat context and affected infrastructure.")

    if vt.get("found"):
        detections = vt.get("detections", 0)
        total = vt.get("total_engines", 0)
        recs.append(f"VirusTotal: {detections}/{total} AV engines flagged this IoC. Cross-reference with endpoint detection logs.")

    if severity == "clean":
        recs.append("No threat intelligence hits found. IoC appears clean across all checked feeds.")
        recs.append("Continue monitoring — absence of findings does not guarantee safety for newly registered domains or IPs.")
    elif severity == "low" and not recs:
        recs.append("Low threat score. Monitor for recurrence but no immediate action required.")

    return recs[:3]
