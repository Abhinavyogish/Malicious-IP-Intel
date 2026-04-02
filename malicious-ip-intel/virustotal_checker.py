import requests
import time
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
import config

_BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses"
_EMPTY_RESULT = {"vt_malicious": None, "vt_total_engines": None}


def check_ip(ip: str) -> dict:
    """
    Query VirusTotal for a single IP.
    Returns dict with: vt_malicious, vt_total_engines.
    All values are None if the request fails.
    Handles HTTP 429 with one 60s retry (VirusTotal free tier: 4 req/min).
    AbuseIPDB 429 is treated as plain failure (generous 1000/day limit).
    """
    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}
    url = f"{_BASE_URL}/{ip}"

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 429:
            print(f"[VirusTotal] Rate limited for {ip}. Sleeping {config.VT_RETRY_SLEEP_SECONDS}s then retrying...")
            time.sleep(config.VT_RETRY_SLEEP_SECONDS)
            response = requests.get(url, headers=headers, timeout=10)

        if response.status_code != 200:
            print(f"[VirusTotal] Non-200 response for {ip}: {response.status_code}")
            return _EMPTY_RESULT.copy()

        stats = (
            response.json()
            .get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        total = sum(stats.get(k, 0) for k in ("malicious", "suspicious", "undetected", "harmless", "timeout"))
        return {
            "vt_malicious": stats.get("malicious", 0),
            "vt_total_engines": total,
        }
    except Exception as e:
        print(f"[VirusTotal] Error checking {ip}: {e}")
        return _EMPTY_RESULT.copy()
