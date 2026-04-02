import sys, os
sys.path.insert(0, os.path.dirname(__file__))
import config

SAFE = "Safe"
SUSPICIOUS = "Suspicious"
MALICIOUS = "Malicious"
UNKNOWN = "Unknown"


def classify(abuse_score, vt_malicious) -> str:
    """
    Classify an IP based on AbuseIPDB score and VirusTotal malicious engine count.
    Either value may be None if the corresponding API call failed.
    Returns one of: Safe, Suspicious, Malicious, Unknown.
    """
    if abuse_score is None and vt_malicious is None:
        return UNKNOWN

    # Treat None as neutral (0) for partial-failure cases
    a = abuse_score if abuse_score is not None else 0
    v = vt_malicious if vt_malicious is not None else 0

    if a >= config.MALICIOUS_ABUSE_SCORE or v >= config.MALICIOUS_VT_ENGINES:
        return MALICIOUS
    if a >= config.SUSPICIOUS_ABUSE_SCORE or v >= config.SUSPICIOUS_VT_ENGINES:
        return SUSPICIOUS
    return SAFE


def get_recommendation(verdict: str) -> str:
    recommendations = {
        MALICIOUS: "Block IP immediately via firewall rule; add to deny list; investigate prior connections.",
        SUSPICIOUS: "Monitor closely; rate-limit traffic; flag for manual review.",
        SAFE: "No action required.",
        UNKNOWN: "Unable to classify automatically; retry query manually or investigate with an alternative tool.",
    }
    return recommendations.get(verdict, "No action required.")
