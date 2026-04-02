import csv
import os
from datetime import datetime
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
import sys
sys.path.insert(0, os.path.dirname(__file__))
import config

# Verdict colour map for the PDF table
_VERDICT_COLORS = {
    "Malicious":  colors.HexColor("#FF4C4C"),
    "Suspicious": colors.HexColor("#FFA500"),
    "Safe":       colors.HexColor("#28A745"),
    "Unknown":    colors.HexColor("#AAAAAA"),
}


def write_csv(results: list, path: str):
    """Write results list to CSV. Each result is a dict from main.py."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fieldnames = ["ip", "abuse_score", "vt_malicious", "vt_total_engines",
                  "country", "isp", "verdict", "recommendation"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    print(f"[Report] CSV saved to {path}")


def generate_pdf(results: list, path: str):
    """Generate a 10-section PDF report using reportlab."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    doc = SimpleDocTemplate(path, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story = []

    def h1(text):
        return Paragraph(text, styles["Title"])

    def h2(text):
        return Paragraph(text, styles["Heading1"])

    def body(text):
        return Paragraph(text, styles["BodyText"])

    def gap(n=0.4):
        return Spacer(1, n*cm)

    # Section 1: Title Page
    story += [
        gap(3),
        h1("Malicious IP Intelligence System"),
        gap(0.3),
        body(f"<b>Date:</b> {datetime.now().strftime('%d %B %Y')}"),
        body("<b>Classification:</b> Threat Intelligence Report"),
        body("<b>Tools:</b> AbuseIPDB v2 | VirusTotal v3 | Python 3"),
        gap(2),
    ]

    # Section 2: Introduction
    story += [
        h2("2. Introduction to Threat Intelligence"),
        gap(),
        body(
            "Threat intelligence is the collection, processing, and analysis of data about threats "
            "and threat actors. IP reputation intelligence helps security teams identify network "
            "connections associated with malicious activity — such as botnets, scanning tools, "
            "phishing infrastructure, and command-and-control servers — before they cause harm. "
            "This report presents the results of automated IP reputation lookups performed against "
            "a sample network access log."
        ),
        gap(),
    ]

    # Section 3: Tools and APIs
    story += [
        h2("3. Tools and APIs Used"),
        gap(),
        body("<b>Python 3</b> — scripting language used to orchestrate the analysis pipeline."),
        body("<b>AbuseIPDB (v2)</b> — community-driven IP blacklist with confidence scores (0-100). "
             "Endpoint: api.abuseipdb.com/api/v2/check"),
        body("<b>VirusTotal (v3)</b> — aggregates 70+ antivirus and threat engines for IP reputation. "
             "Endpoint: www.virustotal.com/api/v3/ip_addresses/{ip}"),
        body("<b>reportlab</b> — Python library for programmatic PDF generation."),
        gap(),
    ]

    # Section 4: Methodology
    story += [
        h2("4. Methodology"),
        gap(),
        body("1. <b>Log Parsing:</b> A regex pattern extracted all unique public IPv4 addresses "
             "from the sample network log. Private/RFC1918 addresses were excluded automatically."),
        body("2. <b>API Queries:</b> Each public IP was checked against AbuseIPDB and VirusTotal. "
             "A 15-second delay was enforced between VirusTotal calls to respect the free-tier "
             "rate limit of 4 requests per minute."),
        body("3. <b>Classification:</b> IPs were classified using threshold logic: "
             "AbuseIPDB score >= 80 or VirusTotal malicious engines >= 5 = Malicious; "
             "score 20-79 or engines 1-4 = Suspicious; otherwise = Safe."),
        body("4. <b>Reporting:</b> Results were written to a CSV file and this PDF report."),
        gap(),
    ]

    # Section 5: Script Explanation
    story += [
        h2("5. Python Script Explanation"),
        gap(),
        body("<b>config.py</b> — stores API keys and classification thresholds as named constants."),
        body("<b>log_parser.py</b> — uses a compiled IPv4 regex to extract all IP addresses from "
             "log text, filters out RFC1918 private ranges, and returns a deduplicated list."),
        body("<b>abuseipdb_checker.py</b> — sends an authenticated GET request to the AbuseIPDB "
             "v2 endpoint and returns the confidence score, report count, country, and ISP."),
        body("<b>virustotal_checker.py</b> — queries the VirusTotal v3 IP endpoint, extracts the "
             "last_analysis_stats block, and computes the total number of scanning engines."),
        body("<b>classifier.py</b> — applies threshold logic to the two API scores and returns "
             "a verdict string. Handles partial API failures gracefully."),
        body("<b>report_generator.py</b> — writes results.csv and builds this PDF report using reportlab."),
        body("<b>main.py</b> — orchestrates the pipeline: parse -> query -> classify -> report."),
        gap(),
    ]

    # Section 6: Screenshots placeholder
    story += [
        h2("6. Screenshots of Script Execution"),
        gap(),
        body("[Add screenshots of the terminal output here after running: python main.py]"),
        gap(),
    ]

    # Section 7: Malicious IPs Detected
    malicious = [r for r in results if r["verdict"] == "Malicious"]
    story += [
        h2("7. List of Malicious IPs Detected"),
        gap(),
        body(f"Total IPs analysed: <b>{len(results)}</b>"),
        body(f"Malicious: <b>{len(malicious)}</b>"),
        body(f"Suspicious: <b>{len([r for r in results if r['verdict'] == 'Suspicious'])}</b>"),
        body(f"Safe: <b>{len([r for r in results if r['verdict'] == 'Safe'])}</b>"),
        body(f"Unknown: <b>{len([r for r in results if r['verdict'] == 'Unknown'])}</b>"),
        gap(),
    ]

    # Full results table
    table_data = [["IP Address", "Abuse Score", "VT Malicious", "Country", "Verdict"]]
    for r in results:
        table_data.append([
            r["ip"],
            "N/A" if r["abuse_score"] is None else str(r["abuse_score"]),
            "N/A" if r["vt_malicious"] is None else str(r["vt_malicious"]),
            r["country"] or "N/A",
            r["verdict"],
        ])

    tbl = Table(table_data, colWidths=[4*cm, 2.5*cm, 2.5*cm, 2.5*cm, 3*cm])
    tbl_style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 8),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
        ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for i, r in enumerate(results, start=1):
        verdict_col = 4
        bg = _VERDICT_COLORS.get(r["verdict"], colors.white)
        tbl_style.append(("BACKGROUND", (verdict_col, i), (verdict_col, i), bg))
        tbl_style.append(("TEXTCOLOR",  (verdict_col, i), (verdict_col, i), colors.white))
    tbl.setStyle(TableStyle(tbl_style))
    story += [tbl, gap()]

    # Section 8: Risk Analysis
    story += [
        h2("8. Risk Analysis"),
        gap(),
        body(
            "Malicious IPs represent active threats — these are addresses with high abuse "
            "confidence scores or detection by multiple antivirus engines. They may be associated "
            "with botnets, scanners, exploit kits, or command-and-control infrastructure. "
            "Suspicious IPs show moderate scores and may represent low-level scanning, "
            "compromised hosts, or misconfigured services. Safe IPs returned clean results "
            "from both intelligence sources at the time of query; this does not guarantee "
            "they will remain clean in future."
        ),
        gap(),
    ]

    # Section 9: Mitigation and Recommendations
    story += [
        h2("9. Mitigation and Recommendations"),
        gap(),
    ]
    mit_data = [["Verdict", "Recommended Action"]]
    mit_data += [
        ["Malicious", "Block immediately via firewall deny rule. Add to IP blocklist. Investigate historical connections from this IP in logs."],
        ["Suspicious", "Monitor traffic from this IP. Apply rate-limiting. Flag for manual analyst review."],
        ["Safe",       "No immediate action required. Continue routine monitoring."],
        ["Unknown",    "Unable to classify. Retry query manually or use an alternative threat intelligence tool."],
    ]
    mit_tbl = Table(mit_data, colWidths=[3*cm, 12*cm])
    mit_tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 8),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN",      (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",  (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
    ]))
    story += [mit_tbl, gap()]

    # Section 10: Conclusion
    story += [
        h2("10. Conclusion"),
        gap(),
        body(
            "This automated threat intelligence system successfully parsed network log data, "
            "queried two independent IP reputation APIs, and classified each IP address based "
            "on objective scoring thresholds. The use of both AbuseIPDB and VirusTotal provides "
            "cross-validated results, reducing the risk of false positives from any single source. "
            "Organisations should integrate IP reputation checks into their SIEM or firewall "
            "workflows and subscribe to automated threat feed updates to maintain current coverage. "
            "Regular re-evaluation of blocked IPs is also recommended, as threat actors rotate "
            "infrastructure frequently."
        ),
        gap(),
    ]

    doc.build(story)
    print(f"[Report] PDF saved to {path}")
