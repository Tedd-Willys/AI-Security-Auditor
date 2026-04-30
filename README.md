# AI Security Auditor Enterprise V2.1

AI Security Auditor Enterprise V2.1 is an AI-assisted cybersecurity reconnaissance and reporting tool that combines Nmap service detection, public threat-intelligence enrichment, deterministic risk scoring, and LLM-assisted reporting.

It is designed to reduce analyst workload by turning raw reconnaissance data into structured, evidence-based audit reports.

## What Changed in V2.1

V2.1 improves the original notebook prototype by adding:

- Safer target validation
- DNS/IP safety checks
- No hardcoded API keys
- No shell=True command execution
- Nmap service/version scanning
- CVE extraction from scan output
- CISA Known Exploited Vulnerabilities correlation
- Threat intelligence enrichment
- Optional VirusTotal, AbuseIPDB, and Shodan enrichment
- Deterministic risk scoring before AI analysis
- Structured Markdown and JSON report output
- AI prompts constrained to observed evidence
- Ethical-use confirmation before scanning

## Why This Project Matters

Security analysts often receive noisy scanner output that still requires manual interpretation. This tool explores how AI can assist in security operations by converting raw scan data into clearer findings, risk drivers, and remediation priorities while keeping deterministic scoring separate from AI-generated narrative.

## Current Intelligence Sources

Public/no-key sources:

- URLHaus
- OpenPhish
- PhishTank, where reachable
- AlienVault OTX public endpoint
- ThreatFox
- CISA KEV

Optional API-backed sources:

- VirusTotal
- AbuseIPDB
- Shodan

The tool is built so unavailable or rate-limited feeds fail gracefully instead of breaking the audit.

## Security Engineering Concepts Demonstrated

- Attack surface discovery
- Service/version enumeration
- IOC and threat-intelligence enrichment
- CVE extraction
- Known-exploited vulnerability correlation
- Deterministic risk scoring
- Evidence-based remediation prioritization
- Secure input handling
- Command injection prevention
- AI-assisted reporting with hallucination controls

## Installation

System dependency:

    sudo apt-get update
    sudo apt-get install -y nmap

Python dependencies:

    pip install -r requirements.txt

Environment variables:

    export OPENROUTER_API_KEY="your_key_here"
    export OPENROUTER_MODEL="meta-llama/llama-3-8b-instruct"

Optional enrichment:

    export VIRUSTOTAL_API_KEY="your_key_here"
    export ABUSEIPDB_API_KEY="your_key_here"
    export SHODAN_API_KEY="your_key_here"

## Usage

    python main.py

Recommended first target:

    scanme.nmap.org

## Output

Each audit creates:

- A Markdown report for human review
- A JSON report for automation or downstream processing

Reports are saved under:

    reports/

## Ethical Use

This project is for authorized security testing, defensive reconnaissance, academic work, and portfolio demonstration.

Do not scan systems you do not own or do not have permission to assess.

## Important Limitations

This tool is not a replacement for a professional penetration test.

- Nmap version detection can be imperfect.
- Public feeds can be incomplete or rate-limited.
- CVE matches require manual validation against exact versions.
- LLM analysis must be reviewed by a human analyst.
- Optional commercial/premium sources require user-provided API keys.

## Future Improvements

- EPSS and CVSS enrichment
- HTML/PDF report export
- Dashboard view
- Asset inventory mode
- Better vulnerability deduplication
- Authenticated scanning support
- SIEM export format
- Scan profiles for internal, external, and cloud assets

## Author

Tedd-Willys
MSc Information Technology - Cybersecurity
Carnegie Mellon University Africa
