# Malicious IP Intelligence System

Automated threat intelligence pipeline that checks IP addresses against AbuseIPDB and VirusTotal, classifies them as Safe / Suspicious / Malicious, and generates a report.

## What it does

1. Parses public IPs from a network access log
2. Queries AbuseIPDB (abuse confidence score) and VirusTotal (engine detections)
3. Classifies each IP using threshold logic
4. Outputs a CSV and PDF report with verdicts and mitigation recommendations

## Setup
```bash
cd malicious-ip-intel
pip install -r requirements.txt
```

Set your API keys as environment variables (or they fall back to the defaults in config.py):
```bash
set ABUSEIPDB_KEY=your_key_here
set VIRUSTOTAL_KEY=your_key_here
```

## Run
```bash
py main.py
```

Output is saved to `output/results.csv` and `output/report.pdf`.

## Results (sample run)

| Verdict | Count |
|---------|-------|
| Malicious | 4 |
| Suspicious | 5 |
| Safe | 5 |

Top malicious IPs detected: `185.220.101.34` (Tor exit, AbuseIPDB: 100), `89.248.167.131` (VT: 21 engines), `80.82.77.33` (VT: 15 engines).

## Tools

Python · AbuseIPDB API v2 · VirusTotal API v3 · ipwhois · reportlab