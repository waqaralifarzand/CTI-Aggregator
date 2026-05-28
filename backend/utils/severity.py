def compute_score(feed_results: dict) -> int:
    score = 0

    otx = feed_results.get("otx", {})
    urlhaus = feed_results.get("urlhaus", {})
    malwarebazaar = feed_results.get("malwarebazaar", {})

    # OTX found base points
    if otx.get("found"):
        score += 20

        # OTX pulse count bonus (higher value only)
        pulse_count = otx.get("pulse_count", 0) or 0
        if pulse_count > 20:
            score += 25
        elif pulse_count > 5:
            score += 15

        # OTX dangerous tag bonus
        threat_tags = otx.get("threat_tags", []) or []
        dangerous_tags = {"c2", "botnet", "ransomware", "rat"}
        if any(tag.lower() in dangerous_tags for tag in threat_tags):
            score += 15

    # URLhaus found
    urlhaus_found = urlhaus.get("found", False)
    if urlhaus_found:
        score += 30

    # MalwareBazaar found
    malwarebazaar_found = malwarebazaar.get("found", False)
    if malwarebazaar_found:
        score += 35

    # Bonus if both found
    if urlhaus_found and malwarebazaar_found:
        score += 10

    return min(score, 100)


def score_to_severity(score: int) -> str:
    if score == 0:
        return "clean"
    elif score <= 25:
        return "low"
    elif score <= 50:
        return "medium"
    elif score <= 75:
        return "high"
    else:
        return "critical"


def generate_recommendations(severity: str, feed_results: dict) -> list:
    recommendations = []

    otx = feed_results.get("otx", {})
    urlhaus = feed_results.get("urlhaus", {})
    malwarebazaar = feed_results.get("malwarebazaar", {})

    if severity == "clean":
        recommendations.append(
            "No threats detected — continue standard monitoring procedures."
        )
        recommendations.append(
            "Consider re-scanning periodically as threat intelligence updates."
        )
        return recommendations

    if severity in ("critical", "high"):
        recommendations.append(
            "Immediately block this indicator at perimeter firewalls and EDR solutions."
        )
        recommendations.append(
            "Initiate an incident response investigation for any internal assets that contacted this indicator."
        )
    elif severity == "medium":
        recommendations.append(
            "Add this indicator to your watchlist and monitor for associated activity."
        )
        recommendations.append(
            "Review network logs for any historical connections to this indicator."
        )
    else:
        recommendations.append(
            "Flag this indicator for analyst review as a low-confidence threat."
        )

    if otx.get("found"):
        threat_tags = otx.get("threat_tags", []) or []
        pulse_count = otx.get("pulse_count", 0) or 0
        if pulse_count > 5:
            recommendations.append(
                f"OTX reports {pulse_count} threat pulses — correlate with internal SIEM data."
            )
        if threat_tags:
            tag_str = ", ".join(threat_tags[:3])
            recommendations.append(
                f"OTX threat tags include: {tag_str} — cross-reference with threat actor profiles."
            )

    if urlhaus.get("found"):
        url_count = urlhaus.get("url_count", 0) or 0
        recommendations.append(
            f"URLhaus associates this host with {url_count} malicious URL(s) — inspect web proxy logs."
        )

    if malwarebazaar.get("found"):
        sig = malwarebazaar.get("signature") or "unknown"
        recommendations.append(
            f"MalwareBazaar identifies this hash as '{sig}' — scan endpoints for this file."
        )

    # Deduplicate while preserving order and cap at 5
    seen = set()
    unique = []
    for r in recommendations:
        if r not in seen:
            seen.add(r)
            unique.append(r)
        if len(unique) >= 5:
            break

    return unique
