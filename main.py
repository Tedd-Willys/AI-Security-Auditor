
from __future__ import annotations

import os
import re
import json
import ipaddress
import subprocess
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

try:
    from openai import OpenAI
except Exception:
    OpenAI = None


@dataclass
class RiskFinding:
    category: str
    signal: str
    weight: int
    evidence: str
    recommendation: str


class SecurityAuditorV2:
    """
    AI Security Auditor V2

    V2 improvements:
    - No hardcoded API keys
    - Safer target validation
    - No shell=True command execution
    - Nmap fallback logic if optional NSE scripts are missing
    - Deterministic risk scoring before AI analysis
    - Structured JSON + Markdown report output
    - AI prompt constrained to observed evidence to reduce hallucinations
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: str = "meta-llama/llama-3-8b-instruct",
        base_url: str = "https://openrouter.ai/api/v1",
        top_ports: int = 50,
        report_dir: str = "reports",
    ):
        self.api_key = api_key or os.environ.get("OPENROUTER_API_KEY")
        self.model_name = os.environ.get("OPENROUTER_MODEL", model_name)
        self.base_url = base_url
        self.top_ports = top_ports
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(exist_ok=True)

        self.client = None
        if self.api_key and OpenAI is not None:
            self.client = OpenAI(api_key=self.api_key, base_url=self.base_url)

    # -------------------------------
    # 1. Target handling
    # -------------------------------

    def normalize_target(self, target: str) -> str:
        """
        Accepts inputs like:
        - scanme.nmap.org
        - https://scanme.nmap.org/path
        - 45.33.32.156

        Returns only the host/domain/IP part.
        """
        target = target.strip()

        # Remove scheme if user pasted URL
        target = re.sub(r"^https?://", "", target, flags=re.IGNORECASE)

        # Remove path/query if present
        target = target.split("/")[0].split("?")[0].strip()

        # Remove port if target is domain:port, but preserve IPv6 is not supported in this simple version
        if ":" in target and target.count(":") == 1:
            target = target.split(":")[0]

        return target.lower()

    def validate_target(self, target: str) -> str:
        """
        Validate target to reduce command injection and accidental bad input.

        This does NOT prove authorization.
        It only ensures the string looks like a domain or IPv4 address.
        """
        target = self.normalize_target(target)

        if not target:
            raise ValueError("Target cannot be empty.")

        # Block shell/control characters explicitly
        forbidden = [";", "&", "|", "$", "`", "\\", "\n", "\r", ">", "<", "(", ")", "{", "}", "[", "]", " "]
        if any(char in target for char in forbidden):
            raise ValueError(f"Invalid target: suspicious character detected in '{target}'.")

        # IPv4 validation
        try:
            ipaddress.ip_address(target)
            return target
        except ValueError:
            pass

        # Domain validation
        domain_pattern = re.compile(
            r"^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)"
            r"(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))+$"
        )

        if not domain_pattern.match(target):
            raise ValueError(
                f"Invalid target '{target}'. Use a valid domain like scanme.nmap.org or IPv4 address."
            )

        return target

    # -------------------------------
    # 2. Nmap scanning
    # -------------------------------

    def run_nmap_scan(self, target: str, timeout: int = 420) -> Dict[str, Any]:
        """
        Runs Nmap without shell=True.

        First attempts service/version scan with useful NSE scripts.
        If optional scripts are unavailable, falls back to plain -sV.
        """
        target = self.validate_target(target)

        primary_cmd = [
            "nmap",
            "-sV",
            "--top-ports",
            str(self.top_ports),
            "--script",
            "vulners,http-enum",
            target,
        ]

        fallback_cmd = [
            "nmap",
            "-sV",
            "--top-ports",
            str(self.top_ports),
            target,
        ]

        primary = subprocess.run(
            primary_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        primary_output = (primary.stdout or "") + "\n" + (primary.stderr or "")

        # Many default Colab Nmap installs do not include the external "vulners" NSE script.
        # If it fails because of script availability, fall back cleanly.
        if primary.returncode != 0 and ("vulners" in primary_output.lower() or "script" in primary_output.lower()):
            fallback = subprocess.run(
                fallback_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            fallback_output = (fallback.stdout or "") + "\n" + (fallback.stderr or "")

            return {
                "target": target,
                "command_used": " ".join(fallback_cmd),
                "fallback_used": True,
                "return_code": fallback.returncode,
                "raw_output": fallback_output.strip(),
                "note": "Fallback scan used because optional NSE scripts were unavailable.",
            }

        return {
            "target": target,
            "command_used": " ".join(primary_cmd),
            "fallback_used": False,
            "return_code": primary.returncode,
            "raw_output": primary_output.strip(),
            "note": "Primary scan completed.",
        }

    # -------------------------------
    # 3. Parsing
    # -------------------------------

    def parse_open_ports(self, nmap_output: str) -> List[Dict[str, str]]:
        """
        Extract open TCP ports from Nmap text output.
        """
        ports = []

        for line in nmap_output.splitlines():
            match = re.match(r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*)$", line.strip())
            if match:
                ports.append(
                    {
                        "port": match.group(1),
                        "protocol": "tcp",
                        "service": match.group(2),
                        "version": match.group(3).strip(),
                    }
                )

        return ports

    def extract_cves(self, text: str) -> List[str]:
        """
        Extract CVE identifiers from scan output.
        """
        return sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text.upper())))

    # -------------------------------
    # 4. Threat intelligence
    # -------------------------------

    def safe_get(self, url: str, timeout: int = 8) -> Optional[requests.Response]:
        """
        Wrapper for external feed requests.
        """
        try:
            return requests.get(
                url,
                timeout=timeout,
                headers={"User-Agent": "AI-Security-Auditor-V2/1.0"},
            )
        except Exception:
            return None

    def fetch_cisa_kev(self) -> Dict[str, Any]:
        """
        Pulls CISA Known Exploited Vulnerabilities feed.
        """
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        response = self.safe_get(url, timeout=10)

        if not response or response.status_code != 200:
            return {"loaded": False, "count": 0, "cves": []}

        try:
            data = response.json()
            cves = [
                item.get("cveID", "").upper()
                for item in data.get("vulnerabilities", [])
                if item.get("cveID")
            ]

            return {
                "loaded": True,
                "count": len(cves),
                "cves": sorted(set(cves)),
            }
        except Exception:
            return {"loaded": False, "count": 0, "cves": []}

    def fetch_threat_intel(self, target: str, observed_cves: List[str]) -> Dict[str, Any]:
        """
        Checks public reputation sources and correlates observed CVEs with CISA KEV.
        """
        target = self.validate_target(target)

        intel = {
            "urlhaus_match": False,
            "openphish_match": False,
            "alienvault_pulses": 0,
            "cisa_kev_loaded": False,
            "cisa_kev_total": 0,
            "kev_matches": [],
            "feed_errors": [],
        }

        # URLHaus
        urlhaus = self.safe_get("https://urlhaus.abuse.ch/downloads/text/")
        if urlhaus and urlhaus.status_code == 200:
            intel["urlhaus_match"] = target in urlhaus.text
        else:
            intel["feed_errors"].append("URLHaus unavailable or timed out.")

        # OpenPhish
        openphish = self.safe_get("https://openphish.com/feed.txt")
        if openphish and openphish.status_code == 200:
            intel["openphish_match"] = target in openphish.text
        else:
            intel["feed_errors"].append("OpenPhish unavailable or timed out.")

        # AlienVault OTX public endpoint
        otx = self.safe_get(f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/general")
        if otx and otx.status_code == 200:
            try:
                intel["alienvault_pulses"] = int(otx.json().get("pulse_info", {}).get("count", 0))
            except Exception:
                intel["feed_errors"].append("AlienVault response could not be parsed.")
        else:
            intel["feed_errors"].append("AlienVault unavailable or timed out.")

        # CISA KEV correlation
        kev = self.fetch_cisa_kev()
        intel["cisa_kev_loaded"] = kev["loaded"]
        intel["cisa_kev_total"] = kev["count"]

        if kev["loaded"]:
            observed_set = set(cve.upper() for cve in observed_cves)
            kev_set = set(kev["cves"])
            intel["kev_matches"] = sorted(observed_set.intersection(kev_set))

        return intel

    # -------------------------------
    # 5. Deterministic risk scoring
    # -------------------------------

    def score_risk(
        self,
        open_ports: List[Dict[str, str]],
        cves: List[str],
        intel: Dict[str, Any],
        nmap_output: str,
    ) -> Dict[str, Any]:
        """
        Deterministic scoring before AI.

        This is important because the LLM should explain evidence,
        not invent the risk score from nothing.
        """
        findings: List[RiskFinding] = []

        risky_ports = {
            "21": ("FTP exposed", 2, "Replace FTP with SFTP/SSH or restrict access."),
            "22": ("SSH exposed", 1, "Restrict SSH by IP allowlist, enforce MFA/keys, disable password login."),
            "23": ("Telnet exposed", 4, "Disable Telnet immediately; replace with SSH."),
            "25": ("SMTP exposed", 1, "Review relay controls and mail security configuration."),
            "80": ("HTTP exposed", 1, "Redirect HTTP to HTTPS and review web server hardening."),
            "445": ("SMB exposed", 4, "Restrict SMB exposure and verify patching."),
            "3389": ("RDP exposed", 4, "Restrict RDP behind VPN/ZTNA and enforce MFA."),
            "3306": ("MySQL exposed", 3, "Restrict database exposure to trusted hosts only."),
            "5432": ("PostgreSQL exposed", 3, "Restrict database exposure to trusted hosts only."),
            "6379": ("Redis exposed", 4, "Do not expose Redis publicly; require authentication and network isolation."),
            "9200": ("Elasticsearch exposed", 4, "Restrict Elasticsearch access and require authentication."),
            "27017": ("MongoDB exposed", 4, "Restrict MongoDB access and enforce authentication."),
        }

        for item in open_ports:
            port = item["port"]
            if port in risky_ports:
                signal, weight, recommendation = risky_ports[port]
                findings.append(
                    RiskFinding(
                        category="Exposed Service",
                        signal=signal,
                        weight=weight,
                        evidence=f"Port {port}/tcp open: {item.get('service', '')} {item.get('version', '')}",
                        recommendation=recommendation,
                    )
                )

        if cves:
            findings.append(
                RiskFinding(
                    category="Vulnerability Indicators",
                    signal="CVE identifiers observed in scan output",
                    weight=min(5, 2 + len(cves) // 5),
                    evidence=", ".join(cves[:10]) + (" ..." if len(cves) > 10 else ""),
                    recommendation="Validate each CVE against the exact service version and patch exposure first.",
                )
            )

        if intel.get("kev_matches"):
            findings.append(
                RiskFinding(
                    category="Weaponization",
                    signal="Observed CVEs match CISA Known Exploited Vulnerabilities",
                    weight=5,
                    evidence=", ".join(intel["kev_matches"]),
                    recommendation="Prioritize KEV-matched CVEs for immediate remediation or compensating controls.",
                )
            )

        if intel.get("urlhaus_match") or intel.get("openphish_match") or intel.get("alienvault_pulses", 0) > 0:
            hits = []
            if intel.get("urlhaus_match"):
                hits.append("URLHaus")
            if intel.get("openphish_match"):
                hits.append("OpenPhish")
            if intel.get("alienvault_pulses", 0) > 0:
                hits.append(f"AlienVault OTX pulses={intel.get('alienvault_pulses')}")
            findings.append(
                RiskFinding(
                    category="Threat Intelligence",
                    signal="Target appears in one or more threat-intelligence sources",
                    weight=4,
                    evidence=", ".join(hits),
                    recommendation="Investigate reputation hit, validate ownership, and check for compromise or abuse.",
                )
            )

        outdated_signals = []
        lower_output = nmap_output.lower()

        if "apache httpd 2.4.7" in lower_output:
            outdated_signals.append("Apache httpd 2.4.7 observed")
        if "openssh 6.6.1" in lower_output:
            outdated_signals.append("OpenSSH 6.6.1 observed")
        if "ubuntu 14" in lower_output:
            outdated_signals.append("Ubuntu 14.x indicator observed")

        if outdated_signals:
            findings.append(
                RiskFinding(
                    category="Patch Hygiene",
                    signal="Potentially outdated service/version indicators",
                    weight=3,
                    evidence="; ".join(outdated_signals),
                    recommendation="Confirm version accuracy, patch outdated services, and apply compensating controls.",
                )
            )

        raw_score = sum(f.weight for f in findings)
        score = min(10, raw_score)

        if score >= 8:
            severity = "High"
        elif score >= 5:
            severity = "Medium"
        elif score >= 1:
            severity = "Low"
        else:
            severity = "Informational"

        return {
            "score": score,
            "severity": severity,
            "finding_count": len(findings),
            "findings": [asdict(finding) for finding in findings],
        }

    # -------------------------------
    # 6. AI reporting
    # -------------------------------

    def generate_ai_report(
        self,
        target: str,
        open_ports: List[Dict[str, str]],
        cves: List[str],
        intel: Dict[str, Any],
        risk: Dict[str, Any],
        nmap_output: str,
    ) -> str:
        """
        LLM report generation.

        Important:
        The prompt tells the model not to invent CVEs/findings.
        """
        evidence_pack = {
            "target": target,
            "open_ports": open_ports,
            "observed_cves": cves,
            "threat_intel": intel,
            "deterministic_risk": risk,
        }

        if not self.client:
            return self.generate_local_report(evidence_pack)

        prompt = f"""
You are a senior security engineer writing a professional audit report.

Rules:
- Use ONLY the evidence provided below.
- Do NOT invent CVEs, headers, vulnerabilities, exploits, or threat actors.
- If evidence is missing, write "not observed in current scan."
- Focus on attack surface, realistic attack paths, risk, and remediation priority.

Evidence:
{json.dumps(evidence_pack, indent=2)}

Raw Nmap output:
{nmap_output[:6000]}

Write the report with these sections:
1. Executive Summary
2. Attack Surface Overview
3. Key Risk Drivers
4. Realistic Attack Path Hypotheses
5. Remediation Roadmap
   - Immediate
   - Short-term
   - Strategic
6. Validation Notes and Limitations
"""

        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
            )

            return response.choices[0].message.content

        except Exception as exc:
            return (
                "AI report generation failed. Falling back to local report.\n\n"
                + str(exc)
                + "\n\n"
                + self.generate_local_report(evidence_pack)
            )

    def generate_local_report(self, evidence_pack: Dict[str, Any]) -> str:
        """
        Local fallback report if no API key or API failure.
        """
        target = evidence_pack["target"]
        risk = evidence_pack["deterministic_risk"]
        ports = evidence_pack["open_ports"]
        cves = evidence_pack["observed_cves"]
        intel = evidence_pack["threat_intel"]

        lines = [
            f"# AI Security Auditor V2 Report — {target}",
            "",
            "## Executive Summary",
            f"Deterministic risk score: {risk['score']}/10 ({risk['severity']}).",
            "",
            "## Attack Surface Overview",
        ]

        if ports:
            for port in ports:
                lines.append(
                    f"- {port['port']}/tcp open — {port['service']} {port.get('version', '')}".strip()
                )
        else:
            lines.append("- No open TCP ports parsed from the scan output.")

        lines.extend(["", "## CVE Indicators"])

        if cves:
            for cve in cves[:20]:
                lines.append(f"- {cve}")
        else:
            lines.append("- No CVE identifiers observed in current scan output.")

        lines.extend(["", "## Threat Intelligence"])

        lines.append(f"- URLHaus match: {intel.get('urlhaus_match')}")
        lines.append(f"- OpenPhish match: {intel.get('openphish_match')}")
        lines.append(f"- AlienVault pulses: {intel.get('alienvault_pulses')}")
        lines.append(f"- CISA KEV matches: {', '.join(intel.get('kev_matches', [])) or 'None observed'}")

        lines.extend(["", "## Key Risk Drivers"])

        if risk["findings"]:
            for finding in risk["findings"]:
                lines.append(f"- **{finding['category']}**: {finding['signal']}")
                lines.append(f"  - Evidence: {finding['evidence']}")
                lines.append(f"  - Recommendation: {finding['recommendation']}")
        else:
            lines.append("- No deterministic risk findings were generated.")

        lines.extend(
            [
                "",
                "## Validation Notes",
                "- This report is based on unauthenticated reconnaissance.",
                "- Scanner output should be validated manually before remediation decisions.",
                "- This tool is for authorized defensive assessment only.",
            ]
        )

        return "\n".join(lines)

    # -------------------------------
    # 7. Save reports
    # -------------------------------

    def save_reports(self, result: Dict[str, Any]) -> Dict[str, str]:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_target = re.sub(r"[^a-zA-Z0-9_.-]", "_", result["target"])

        json_path = self.report_dir / f"{safe_target}_{timestamp}_audit.json"
        md_path = self.report_dir / f"{safe_target}_{timestamp}_audit.md"

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)

        markdown = [
            f"# AI Security Auditor V2 Report — {result['target']}",
            "",
            f"**Generated:** {result['timestamp_utc']}",
            "",
            f"**Risk Score:** {result['risk']['score']}/10",
            "",
            f"**Severity:** {result['risk']['severity']}",
            "",
            "---",
            "",
            result["ai_report"],
            "",
            "---",
            "",
            "## Raw Evidence Summary",
            "",
            "### Open Ports",
        ]

        if result["open_ports"]:
            for port in result["open_ports"]:
                markdown.append(
                    f"- `{port['port']}/tcp` — `{port['service']}` {port.get('version', '')}".strip()
                )
        else:
            markdown.append("- No open ports parsed.")

        markdown.extend(["", "### Observed CVEs"])

        if result["observed_cves"]:
            for cve in result["observed_cves"]:
                markdown.append(f"- `{cve}`")
        else:
            markdown.append("- No CVE identifiers observed.")

        markdown.extend(["", "### Ethical Use"])
        markdown.append("This tool is intended only for authorized security testing and defensive analysis.")

        with open(md_path, "w", encoding="utf-8") as f:
            f.write("\n".join(markdown))

        return {
            "json_report": str(json_path),
            "markdown_report": str(md_path),
        }

    # -------------------------------
    # 8. Full pipeline
    # -------------------------------

    def run_full_audit(self, target: str) -> Dict[str, Any]:
        target = self.validate_target(target)

        print(f"[*] Starting AI Security Auditor V2 scan for: {target}")
        print("[*] Running Nmap service/version scan...")

        scan = self.run_nmap_scan(target)
        nmap_output = scan["raw_output"]

        print("[*] Parsing open ports and CVE indicators...")
        open_ports = self.parse_open_ports(nmap_output)
        observed_cves = self.extract_cves(nmap_output)

        print("[*] Checking threat intelligence sources...")
        intel = self.fetch_threat_intel(target, observed_cves)

        print("[*] Computing deterministic risk score...")
        risk = self.score_risk(open_ports, observed_cves, intel, nmap_output)

        print("[*] Generating AI-assisted report...")
        ai_report = self.generate_ai_report(
            target=target,
            open_ports=open_ports,
            cves=observed_cves,
            intel=intel,
            risk=risk,
            nmap_output=nmap_output,
        )

        result = {
            "tool": "AI Security Auditor V2",
            "target": target,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "scan": scan,
            "open_ports": open_ports,
            "observed_cves": observed_cves,
            "threat_intel": intel,
            "risk": risk,
            "ai_report": ai_report,
        }

        paths = self.save_reports(result)

        print("[+] Audit complete.")
        print(f"[+] Risk score: {risk['score']}/10 ({risk['severity']})")
        print(f"[+] Markdown report: {paths['markdown_report']}")
        print(f"[+] JSON report: {paths['json_report']}")

        result["report_paths"] = paths
        return result



import os
import socket
import ipaddress
import requests
from typing import Any, Dict, List, Optional


class SecurityAuditorEnterpriseV21(SecurityAuditorV2):
    """
    Enterprise V2.1 upgrade.

    Adds:
    - Safer DNS/IP target validation
    - IOC normalization and source-hit tracking
    - More threat-intel coverage using public feeds
    - Optional premium/API-backed enrichment when keys are present
    - Better risk scoring based on source confidence
    """

    def __init__(self, *args, allow_private_targets: bool = False, **kwargs):
        super().__init__(*args, **kwargs)
        self.allow_private_targets = allow_private_targets or os.environ.get("ALLOW_PRIVATE_TARGETS", "").upper() == "YES"

    def resolve_target_ips(self, target: str) -> List[str]:
        try:
            ipaddress.ip_address(target)
            return [target]
        except ValueError:
            pass

        try:
            records = socket.getaddrinfo(target, None)
            ips = sorted(set(item[4][0] for item in records))
            return ips
        except Exception:
            return []

    def is_restricted_ip(self, ip: str) -> bool:
        try:
            obj = ipaddress.ip_address(ip)
            return (
                obj.is_private
                or obj.is_loopback
                or obj.is_link_local
                or obj.is_multicast
                or obj.is_reserved
                or obj.is_unspecified
            )
        except ValueError:
            return True

    def validate_target(self, target: str) -> str:
        target = super().validate_target(target)

        ips = self.resolve_target_ips(target)
        if ips and not self.allow_private_targets:
            restricted = [ip for ip in ips if self.is_restricted_ip(ip)]
            if restricted:
                raise ValueError(
                    f"Target resolves to restricted/private IP(s): {restricted}. "
                    "For lab/internal testing only, set ALLOW_PRIVATE_TARGETS=YES."
                )

        return target

    def target_type(self, target: str) -> str:
        try:
            obj = ipaddress.ip_address(target)
            return "ip" if obj.version == 4 else "ipv6"
        except ValueError:
            return "domain"

    def add_source_hit(
        self,
        intel: Dict[str, Any],
        source: str,
        hit_type: str,
        confidence: str,
        evidence: str,
    ) -> None:
        intel.setdefault("source_hits", [])
        intel["source_hits"].append(
            {
                "source": source,
                "type": hit_type,
                "confidence": confidence,
                "evidence": evidence[:500],
            }
        )

    def safe_post_json(self, url: str, payload: Dict[str, Any], timeout: int = 10) -> Optional[requests.Response]:
        try:
            return requests.post(
                url,
                json=payload,
                timeout=timeout,
                headers={"User-Agent": "AI-Security-Auditor-V2.1/1.0"},
            )
        except Exception:
            return None

    def fetch_threatfox(self, target: str) -> Dict[str, Any]:
        response = self.safe_post_json(
            "https://threatfox-api.abuse.ch/api/v1/",
            {"query": "search_ioc", "search_term": target},
            timeout=10,
        )

        if not response or response.status_code != 200:
            return {"available": False, "matches": 0, "summary": "ThreatFox unavailable or timed out."}

        try:
            data = response.json()
            entries = data.get("data") or []
            if isinstance(entries, list):
                return {
                    "available": True,
                    "matches": len(entries),
                    "summary": f"{len(entries)} ThreatFox IOC match(es) returned.",
                    "sample": entries[:3],
                }
        except Exception:
            pass

        return {"available": True, "matches": 0, "summary": "No ThreatFox matches parsed."}

    def fetch_virustotal_optional(self, target: str) -> Dict[str, Any]:
        api_key = os.environ.get("VIRUSTOTAL_API_KEY")
        if not api_key:
            return {"enabled": False, "summary": "VIRUSTOTAL_API_KEY not set."}

        target_kind = self.target_type(target)
        if target_kind == "ip":
            endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
        elif target_kind == "domain":
            endpoint = f"https://www.virustotal.com/api/v3/domains/{target}"
        else:
            return {"enabled": True, "error": "IPv6 VirusTotal lookup not implemented in this version."}

        try:
            res = requests.get(endpoint, headers={"x-apikey": api_key}, timeout=12)
            if res.status_code != 200:
                return {"enabled": True, "status_code": res.status_code, "summary": "VirusTotal lookup failed."}

            stats = (
                res.json()
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )

            return {
                "enabled": True,
                "malicious": int(stats.get("malicious", 0)),
                "suspicious": int(stats.get("suspicious", 0)),
                "harmless": int(stats.get("harmless", 0)),
                "summary": f"VT malicious={stats.get('malicious', 0)}, suspicious={stats.get('suspicious', 0)}",
            }
        except Exception as exc:
            return {"enabled": True, "error": str(exc)}

    def fetch_abuseipdb_optional(self, target: str) -> Dict[str, Any]:
        api_key = os.environ.get("ABUSEIPDB_API_KEY")
        if not api_key:
            return {"enabled": False, "summary": "ABUSEIPDB_API_KEY not set."}

        if self.target_type(target) != "ip":
            return {"enabled": True, "summary": "AbuseIPDB skipped because target is not an IP."}

        try:
            res = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": target, "maxAgeInDays": "90"},
                timeout=12,
            )

            if res.status_code != 200:
                return {"enabled": True, "status_code": res.status_code, "summary": "AbuseIPDB lookup failed."}

            data = res.json().get("data", {})
            return {
                "enabled": True,
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "summary": f"Abuse score={data.get('abuseConfidenceScore', 0)}, reports={data.get('totalReports', 0)}",
            }
        except Exception as exc:
            return {"enabled": True, "error": str(exc)}

    def fetch_shodan_optional(self, target: str) -> Dict[str, Any]:
        api_key = os.environ.get("SHODAN_API_KEY")
        if not api_key:
            return {"enabled": False, "summary": "SHODAN_API_KEY not set."}

        if self.target_type(target) != "ip":
            return {"enabled": True, "summary": "Shodan skipped because target is not an IP."}

        try:
            url = f"https://api.shodan.io/shodan/host/{target}"
            res = requests.get(url, params={"key": api_key}, timeout=12)

            if res.status_code != 200:
                return {"enabled": True, "status_code": res.status_code, "summary": "Shodan lookup failed."}

            data = res.json()
            ports = data.get("ports", [])
            vulns = sorted(list((data.get("vulns") or {}).keys()))

            return {
                "enabled": True,
                "ports": ports,
                "vulns": vulns[:30],
                "summary": f"Shodan observed {len(ports)} port(s), {len(vulns)} vuln indicator(s).",
            }
        except Exception as exc:
            return {"enabled": True, "error": str(exc)}

    def fetch_threat_intel(self, target: str, observed_cves: List[str]) -> Dict[str, Any]:
        target = self.validate_target(target)

        intel = {
            "urlhaus_match": False,
            "openphish_match": False,
            "phishtank_match": False,
            "alienvault_pulses": 0,
            "threatfox": {},
            "virustotal": {},
            "abuseipdb": {},
            "shodan": {},
            "cisa_kev_loaded": False,
            "cisa_kev_total": 0,
            "kev_matches": [],
            "source_hits": [],
            "feed_errors": [],
        }

        urlhaus = self.safe_get("https://urlhaus.abuse.ch/downloads/text/")
        if urlhaus and urlhaus.status_code == 200:
            intel["urlhaus_match"] = target in urlhaus.text
            if intel["urlhaus_match"]:
                self.add_source_hit(intel, "URLHaus", "malware_reputation", "high", "Target found in URLHaus feed.")
        else:
            intel["feed_errors"].append("URLHaus unavailable or timed out.")

        openphish = self.safe_get("https://openphish.com/feed.txt")
        if openphish and openphish.status_code == 200:
            intel["openphish_match"] = target in openphish.text
            if intel["openphish_match"]:
                self.add_source_hit(intel, "OpenPhish", "phishing_reputation", "high", "Target found in OpenPhish feed.")
        else:
            intel["feed_errors"].append("OpenPhish unavailable or timed out.")

        phishtank = self.safe_get("http://data.phishtank.com/data/online-valid.csv", timeout=10)
        if phishtank and phishtank.status_code == 200:
            intel["phishtank_match"] = target in phishtank.text
            if intel["phishtank_match"]:
                self.add_source_hit(intel, "PhishTank", "phishing_reputation", "high", "Target found in PhishTank feed.")
        else:
            intel["feed_errors"].append("PhishTank unavailable, blocked, or timed out.")

        otx = self.safe_get(f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/general")
        if otx and otx.status_code == 200:
            try:
                pulses = int(otx.json().get("pulse_info", {}).get("count", 0))
                intel["alienvault_pulses"] = pulses
                if pulses > 0:
                    self.add_source_hit(
                        intel,
                        "AlienVault OTX",
                        "threat_pulse",
                        "medium",
                        f"Target linked to {pulses} OTX pulse(s).",
                    )
            except Exception:
                intel["feed_errors"].append("AlienVault response could not be parsed.")
        else:
            intel["feed_errors"].append("AlienVault unavailable or timed out.")

        intel["threatfox"] = self.fetch_threatfox(target)
        if intel["threatfox"].get("matches", 0) > 0:
            self.add_source_hit(
                intel,
                "ThreatFox",
                "ioc_match",
                "high",
                intel["threatfox"].get("summary", "ThreatFox match observed."),
            )

        kev = self.fetch_cisa_kev()
        intel["cisa_kev_loaded"] = kev["loaded"]
        intel["cisa_kev_total"] = kev["count"]

        if kev["loaded"]:
            observed_set = set(cve.upper() for cve in observed_cves)
            kev_set = set(kev["cves"])
            intel["kev_matches"] = sorted(observed_set.intersection(kev_set))
            if intel["kev_matches"]:
                self.add_source_hit(
                    intel,
                    "CISA KEV",
                    "known_exploited_vulnerability",
                    "very_high",
                    ", ".join(intel["kev_matches"]),
                )

        intel["virustotal"] = self.fetch_virustotal_optional(target)
        if intel["virustotal"].get("enabled"):
            malicious = int(intel["virustotal"].get("malicious", 0) or 0)
            suspicious = int(intel["virustotal"].get("suspicious", 0) or 0)
            if malicious > 0 or suspicious > 0:
                self.add_source_hit(
                    intel,
                    "VirusTotal",
                    "multi_engine_reputation",
                    "high",
                    intel["virustotal"].get("summary", "VT reputation hit."),
                )

        intel["abuseipdb"] = self.fetch_abuseipdb_optional(target)
        if intel["abuseipdb"].get("enabled"):
            score = int(intel["abuseipdb"].get("abuse_confidence_score", 0) or 0)
            if score >= 25:
                self.add_source_hit(
                    intel,
                    "AbuseIPDB",
                    "ip_abuse_reputation",
                    "medium" if score < 75 else "high",
                    intel["abuseipdb"].get("summary", "AbuseIPDB reputation hit."),
                )

        intel["shodan"] = self.fetch_shodan_optional(target)
        if intel["shodan"].get("enabled") and intel["shodan"].get("vulns"):
            self.add_source_hit(
                intel,
                "Shodan",
                "external_exposure",
                "medium",
                intel["shodan"].get("summary", "Shodan vuln indicators observed."),
            )

        return intel

    def score_risk(
        self,
        open_ports: List[Dict[str, str]],
        cves: List[str],
        intel: Dict[str, Any],
        nmap_output: str,
    ) -> Dict[str, Any]:
        risk = super().score_risk(open_ports, cves, intel, nmap_output)

        extra_score = 0
        source_hits = intel.get("source_hits", [])

        for hit in source_hits:
            confidence = hit.get("confidence", "medium")
            if confidence == "very_high":
                extra_score += 4
            elif confidence == "high":
                extra_score += 3
            else:
                extra_score += 2

            risk["findings"].append(
                {
                    "category": "Threat Intelligence Correlation",
                    "signal": f"{hit.get('source')} reported {hit.get('type')}",
                    "weight": 3,
                    "evidence": hit.get("evidence", ""),
                    "recommendation": "Validate ownership, investigate reputation context, and prioritize response if confirmed.",
                }
            )

        risk["score"] = min(10, risk["score"] + extra_score)

        if risk["score"] >= 8:
            risk["severity"] = "High"
        elif risk["score"] >= 5:
            risk["severity"] = "Medium"
        elif risk["score"] >= 1:
            risk["severity"] = "Low"
        else:
            risk["severity"] = "Informational"

        risk["finding_count"] = len(risk["findings"])
        return risk


SecurityAuditorV2 = SecurityAuditorEnterpriseV21

print("[+] Enterprise V2.1 upgrades loaded.")



if __name__ == "__main__":
    print("AI Security Auditor Enterprise V2.1")
    print("AUTHORIZED USE ONLY.")
    print("Recommended safe test target: scanme.nmap.org")

    confirm = input("Type YES to confirm authorized testing: ").strip()
    if confirm.upper() != "YES":
        raise SystemExit("Stopped. Authorized use was not confirmed.")

    target = input("Enter target domain/IP [scanme.nmap.org]: ").strip() or "scanme.nmap.org"

    auditor = SecurityAuditorV2(
        api_key=os.environ.get("OPENROUTER_API_KEY"),
        model_name=os.environ.get("OPENROUTER_MODEL", "meta-llama/llama-3-8b-instruct"),
        top_ports=50,
    )

    result = auditor.run_full_audit(target)
    print("")
    print("Report files:")
    print(result.get("report_paths", {}))
