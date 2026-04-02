import os
import time
import sys

sys.path.insert(0, os.path.dirname(__file__))

import config
from log_parser import parse_log_file
from abuseipdb_checker import check_ip as abuse_check
from virustotal_checker import check_ip as vt_check
from classifier import classify, get_recommendation
from report_generator import write_csv, generate_pdf


def main():
    # Ensure output directory exists
    os.makedirs(config.OUTPUT_DIR, exist_ok=True)

    print("=" * 60)
    print("  Malicious IP Intelligence System")
    print("=" * 60)

    # Step 1: Parse IPs from log
    log_path = os.path.join(os.path.dirname(__file__), config.SAMPLE_LOG_PATH)
    print(f"\n[1/4] Parsing IPs from {log_path} ...")
    ips = parse_log_file(log_path)
    print(f"      Found {len(ips)} unique public IPs to analyse.\n")

    # Step 2: Query APIs and classify
    print(f"[2/4] Querying APIs for {len(ips)} IPs ...")
    print(f"      (15s delay between VirusTotal calls - free tier limit)\n")
    results = []

    for i, ip in enumerate(ips, start=1):
        print(f"  [{i}/{len(ips)}] Checking {ip} ...")

        abuse_data = abuse_check(ip)
        vt_data = vt_check(ip)

        verdict = classify(
            abuse_score=abuse_data["abuse_score"],
            vt_malicious=vt_data["vt_malicious"],
        )
        recommendation = get_recommendation(verdict)

        result = {
            "ip": ip,
            "abuse_score": abuse_data["abuse_score"],
            "vt_malicious": vt_data["vt_malicious"],
            "vt_total_engines": vt_data["vt_total_engines"],
            "country": abuse_data["country"],
            "isp": abuse_data["isp"],
            "verdict": verdict,
            "recommendation": recommendation,
        }
        results.append(result)
        print(f"         -> Verdict: {verdict}")

        # Rate-limit: sleep between VT calls (except after the last IP)
        if i < len(ips):
            time.sleep(config.VT_SLEEP_SECONDS)

    # Step 3: Write CSV
    print(f"\n[3/4] Writing results CSV ...")
    csv_path = os.path.join(os.path.dirname(__file__), config.RESULTS_CSV_PATH)
    write_csv(results, csv_path)

    # Step 4: Generate PDF report
    print(f"[4/4] Generating PDF report ...")
    pdf_path = os.path.join(os.path.dirname(__file__), config.REPORT_PDF_PATH)
    generate_pdf(results, pdf_path)

    # Summary
    malicious = [r for r in results if r["verdict"] == "Malicious"]
    suspicious = [r for r in results if r["verdict"] == "Suspicious"]
    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    print(f"  Total IPs analysed : {len(results)}")
    print(f"  Malicious          : {len(malicious)}")
    print(f"  Suspicious         : {len(suspicious)}")
    print(f"  Safe               : {len([r for r in results if r['verdict'] == 'Safe'])}")
    print(f"  Unknown            : {len([r for r in results if r['verdict'] == 'Unknown'])}")
    print(f"\n  Results CSV : {csv_path}")
    print(f"  Report PDF  : {pdf_path}")
    print("=" * 60)

    if malicious:
        print("\n  MALICIOUS IPs DETECTED:")
        for r in malicious:
            print(f"    {r['ip']} (Abuse: {r['abuse_score']}, VT: {r['vt_malicious']})")


if __name__ == "__main__":
    main()
