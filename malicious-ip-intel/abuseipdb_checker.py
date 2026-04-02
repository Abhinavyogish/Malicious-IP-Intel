import requests
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
import config

_BASE_URL = "https://api.abuseipdb.com/api/v2/check"
_EMPTY_RESULT = {"abuse_score": None, "total_reports": None, "country": None, "isp": None}


def check_ip(ip: str) -> dict:
    """
    Query AbuseIPDB for a single IP.
    Returns dict with: abuse_score, total_reports, country, isp.
    All values are None if the request fails.
    """
    headers = {"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": config.ABUSEIPDB_MAX_AGE_DAYS}

    try:
        response = requests.get(_BASE_URL, headers=headers, params=params, timeout=10)
        if response.status_code != 200:
            print(f"[AbuseIPDB] Non-200 response for {ip}: {response.status_code}")
            return _EMPTY_RESULT.copy()
        data = response.json().get("data", {})
        return {
            "abuse_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
        }
    except Exception as e:
        print(f"[AbuseIPDB] Error checking {ip}: {e}")
        return _EMPTY_RESULT.copy()
