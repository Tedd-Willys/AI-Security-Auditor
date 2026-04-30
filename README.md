# AI-Driven Autonomous Security Auditor

An AI-assisted cybersecurity reconnaissance and reporting tool that combines network scanning, threat intelligence checks, and LLM-based analysis to generate structured security audit reports.

## Overview

This project automates early-stage security reconnaissance by collecting technical scan data, checking global threat intelligence sources, and using an LLM to convert raw findings into a readable security report.

The tool currently supports:

- Domain/host reconnaissance
- Nmap service/version scanning
- NSE-based vulnerability correlation
- Threat intelligence checks using sources such as URLHaus, PhishTank, OpenPhish, AlienVault OTX, and CISA KEV
- AI-generated executive security reports
- Risk scoring and remediation guidance

## Why I Built This

Security teams often deal with raw scanner output that requires manual interpretation before it becomes useful for decision-making. This project explores how AI can assist in transforming reconnaissance data into clearer, prioritized reports that connect technical findings to risk and remediation.

## Features

- Automated Nmap scanning with service/version detection
- Threat reputation checks against public intelligence feeds
- CVE and exploitability-oriented analysis
- AI-generated audit reports
- Executive summary, attack surface analysis, and remediation roadmap
- Basic input sanitization to reduce command injection risk

## Tech Stack

- Python
- Nmap / NSE scripts
- OpenAI-compatible LLM API via OpenRouter
- Llama-3 / GPT-style model orchestration
- Public threat intelligence feeds
- Google Colab / GitHub workflow

## Example Workflow

1. User enters one or more target domains.
2. The tool runs reconnaissance and vulnerability scanning.
3. Threat intelligence feeds are checked for malicious reputation.
4. Scan and intel data are passed to an LLM.
5. A structured audit report is generated with risk scoring and remediation recommendations.

## Example Output Sections

- Executive Risk Score
- Attack Surface Analysis
- Vulnerability & CVE Correlation
- Technical Exploitation Path
- Immediate vs Strategic Remediation Plan

## Security & Ethical Use

This project is intended for educational, defensive, and authorized security testing only. Do not scan systems without permission.

## Current Limitations

- AI-generated findings require human validation.
- CVE correlation depends on scan accuracy and version detection.
- Public threat intelligence feeds may be incomplete or unavailable.
- The current implementation is a prototype and not a replacement for a full professional penetration test.

## Future Improvements

- Add structured JSON output
- Improve false-positive handling
- Add severity scoring using CVSS/EPSS
- Add report export to PDF/HTML
- Add dashboard visualizations
- Add authenticated scanning support
- Improve safe target validation and scan scope controls

## Author

Tedd Willys Handa Mulitani  
MSc Information Technology - Cybersecurity  
Carnegie Mellon University Africa
