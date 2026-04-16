import subprocess
import os
import re
import requests
import json
from datetime import datetime
from openai import OpenAI

class SecurityAuditorPro:
    def __init__(self, api_key, model_name="meta-llama/llama-3-8b-instruct", base_url="https://openrouter.ai/api/v1"):
        self.client = OpenAI(api_key=api_key, base_url=base_url)
        self.model_name = model_name
        self.report_file = "enterprise_audit_report.txt"

    def _sanitize_input(self, target):
        return re.sub(r'[^a-zA-Z0-9.-]', '', target)

    def fetch_global_threat_intel(self, target):
        intel_hits = []
        try:
            uh = requests.get("https://urlhaus.abuse.ch/downloads/text/", timeout=5)
            if target in uh.text: intel_hits.append("🚨 [URLHaus] ACTIVE MALWARE NODE")
        except: pass
        return "\n".join(intel_hits) if intel_hits else "✅ Clean"

    def run_vulnerability_scan(self, target):
        target = self._sanitize_input(target)
        try:
            cmd = f"nmap -sV --top-ports 50 --script vulners {target}"
            return subprocess.check_output(cmd.split(), timeout=400).decode()
        except Exception as e: return str(e)

    def run_full_audit(self, target):
        intel = self.fetch_global_threat_intel(target)
        scan = self.run_vulnerability_scan(target)
        # Logic for AI report generation would go here
        return f"Audit for {target}\nIntel: {intel}\nScan: {scan}"
