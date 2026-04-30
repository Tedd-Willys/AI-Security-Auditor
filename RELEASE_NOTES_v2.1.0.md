# Release Notes — v2.1.0

## Summary

This release moves the project from a basic AI-assisted notebook prototype to a cleaner security engineering tool with safer scanning, richer enrichment, structured reporting, and better risk logic.

## Added

- Enterprise V2.1 enrichment layer
- Safer DNS/IP target validation
- Public threat-intelligence correlation
- Optional VirusTotal, AbuseIPDB, and Shodan support
- CISA KEV correlation
- Source-hit tracking
- Confidence-weighted risk scoring
- Markdown and JSON reports

## Security Improvements

- Removed hardcoded secrets
- Added environment-based secret handling
- Avoided shell=True execution
- Added target safety controls
- Added ethical-use confirmation
- Constrained AI report generation to observed evidence

## Notes

This release is intended for authorized assessment only.
