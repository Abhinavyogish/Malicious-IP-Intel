import os

# API Keys — for local lab use. Do not commit real keys to shared repositories.
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_KEY", "845c08cd6dd4cba5f02b98eac6311b4a8c5adc58c8d71b494286f04d32e070838af818b23097798c")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_KEY", "466b07dedad856d6cc82b832ae7b0dd25d48a6b4ccee6fa95360022b2f468352")

# Classification thresholds
MALICIOUS_ABUSE_SCORE = 80
MALICIOUS_VT_ENGINES = 5
SUSPICIOUS_ABUSE_SCORE = 20
SUSPICIOUS_VT_ENGINES = 1

# Rate limiting
VT_SLEEP_SECONDS = 15
VT_RETRY_SLEEP_SECONDS = 60

# AbuseIPDB query window
ABUSEIPDB_MAX_AGE_DAYS = 90

# Paths
SAMPLE_LOG_PATH = "sample_logs/network.log"
OUTPUT_DIR = "output"
RESULTS_CSV_PATH = "output/results.csv"
REPORT_PDF_PATH = "output/report.pdf"
