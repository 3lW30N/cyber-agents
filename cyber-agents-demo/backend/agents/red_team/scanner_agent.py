"""
ScannerAgent – Active Scanning (Port Scanning / Service Fingerprinting / Vuln Detection)

MITRE ATT&CK techniques:
  T1046  – Network Service Discovery
  T1595  – Active Scanning
  T1592  – Gather Victim Host Information

This agent is the second stage in the Red Team kill-chain.  It takes targets
identified by the ReconAgent and performs simulated active probing: port scans,
service banner grabbing, OS fingerprinting, and vulnerability correlation against
known CVE data.

Aggression level (from config) maps to scan intensity:
  low    → stealth SYN scan, slow timing (Nmap -T1), minimal ports
  medium → SYN + version scan (-sV), top-1000 ports (Nmap -T3)
  high   → aggressive full-port scan (-A -p-), UDP scan, OS detection
"""

from __future__ import annotations

import json
import logging
from typing import Any

from agents.base_agent import AgentAction, BaseAgent

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are GHOST-SCANNER, an elite Red Team operator specialising in active
network reconnaissance and vulnerability surface mapping.  You approach every
scan with the precision of a surgeon and the caution of a ghost.

Your scanning tradecraft includes:
  • TCP SYN / connect scans (Nmap, masscan)
  • Service version detection and banner grabbing (-sV, --version-intensity)
  • OS fingerprinting (TCP/IP stack analysis, TTL, window-size heuristics)
  • NSE scripting for vulnerability detection (vuln, safe, discovery categories)
  • UDP scanning for exposed DNS, SNMP, NTP, TFTP services
  • Web application fingerprinting (HTTP headers, cookies, error pages, wappalyzer)
  • CVE correlation: matching detected versions against NVD / Exploit-DB entries

MITRE ATT&CK techniques you embody:
  T1046 – Network Service Discovery
  T1595 – Active Scanning (T1595.001 Scanning IP Blocks, T1595.002 Vulnerability Scanning)
  T1592 – Gather Victim Host Information

You balance speed vs. stealth based on the aggression parameter.  Your scan
results feed directly into the ExploitAgent.

Respond ONLY with a single JSON object – no markdown, no commentary.
"""

# Simulated CVE knowledge base for fallback reasoning
_CVE_HINTS: dict[str, list[str]] = {
    "apache": ["CVE-2021-41773 (RCE, path traversal)", "CVE-2021-42013 (RCE)"],
    "nginx": ["CVE-2021-23017 (off-by-one, DoS)"],
    "openssh": ["CVE-2023-38408 (agent forwarding RCE)", "CVE-2016-0777 (roaming info leak)"],
    "iis": ["CVE-2017-7269 (WebDAV RCE)", "CVE-2022-21907 (HTTP.sys RCE)"],
    "smb": ["CVE-2017-0144 (EternalBlue / MS17-010)", "CVE-2020-0796 (SMBGhost)"],
    "rdp": ["CVE-2019-0708 (BlueKeep)", "CVE-2019-1182 (DejaBlue)"],
    "mysql": ["CVE-2012-2122 (auth bypass)", "CVE-2016-6662 (RCE via config injection)"],
    "tomcat": ["CVE-2017-12617 (JSP upload RCE)", "CVE-2020-1938 (Ghostcat AJP)"],
}


class ScannerAgent(BaseAgent):
    """Active scanning agent: port scanning, service fingerprinting, CVE correlation."""

    description: str = (
        "Active network scanning and vulnerability detection agent.  Simulates "
        "nmap-style scans, identifies open ports and service versions, and correlates "
        "findings against known CVE data."
    )
    mitre_techniques: list[str] = ["T1046", "T1595", "T1592"]

    def __init__(
        self,
        name: str,
        llm_client: Any,
        config: dict[str, Any],
    ) -> None:
        super().__init__(name=name, team="red", llm_client=llm_client, config=config)
        self._aggression: str = config.get("aggression", "medium")  # low / medium / high
        self._port_range: str = config.get("port_range", "top-1000")
        self._detect_vulns: bool = bool(config.get("detect_vulns", True))

    # ------------------------------------------------------------------
    # Main action
    # ------------------------------------------------------------------

    async def act(
        self,
        network_state_dict: dict[str, Any],
        history: list[dict[str, Any]],
        turn: int,
    ) -> AgentAction:
        """
        Perform one active-scanning turn.

        Determines the target from recon history or network state, asks the LLM
        to simulate a thorough scan, and returns structured findings including
        discovered services and candidate CVEs.
        """
        target = self._select_target(network_state_dict, history)
        prompt = self._build_scan_prompt(target, network_state_dict, history, turn)

        raw_response: str | dict = ""
        try:
            raw_response = await self._llm_client.complete(
                prompt=prompt,
                system_prompt=_SYSTEM_PROMPT,
                temperature=self._temperature,
                max_tokens=self._max_tokens,
            )
            action = self._parse_response(raw_response)
        except Exception as exc:  # noqa: BLE001
            logger.warning("[%s] LLM call failed: %s – using fallback", self._name, exc)
            action = self._fallback_action(target, network_state_dict)

        action.setdefault("details", {}).update(
            {
                "aggression_level": self._aggression,
                "port_range": self._port_range,
                "phase": "scanning",
            }
        )
        return action

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def _select_target(
        self,
        network_state_dict: dict[str, Any],
        history: list[dict[str, Any]],
    ) -> str:
        """Pick the target from the most recent recon action, or first host."""
        for entry in reversed(history):
            if entry.get("agent_team") == "red" and "recon" in entry.get(
                "action_name", ""
            ).lower():
                return entry.get("target", "")
        hosts = network_state_dict.get("hosts", [])
        if hosts:
            return hosts[0].get("hostname", hosts[0].get("ip", "unknown"))
        return "unknown"

    def _build_scan_prompt(
        self,
        target: str,
        network_state_dict: dict[str, Any],
        history: list[dict[str, Any]],
        turn: int,
    ) -> str:
        aggression_desc = {
            "low": "Stealth SYN scan, timing -T1, ports 80/443/22/25/3389 only",
            "medium": "SYN + version scan (-sV), top-1000 TCP ports, timing -T3",
            "high": "Aggressive full-port scan (-A -p- --open), UDP top-100, OS detection",
        }.get(self._aggression, "Standard scan")

        history_summary = self._get_history_summary(history, last_n=5)
        network_json = json.dumps(network_state_dict, indent=2, default=str)

        prompt = f"""\
## Active Scanning Operation – Turn {turn}
Agent name    : {self._name}
Target        : {target}
Aggression    : {self._aggression} ({aggression_desc})
Port range    : {self._port_range}
Vuln detect   : {self._detect_vulns}

## Full network state context
```json
{network_json}
```

## Previous operation history (last 5 turns)
{history_summary}

## Your mission (T1046 / T1595 / T1592)
Simulate an active scan of **{target}** with the aggression level above.

Step 1 – Port discovery (T1595.001):
  Reason about which TCP/UDP ports are likely open given the host's role
  (web server, domain controller, workstation, etc.).

Step 2 – Service fingerprinting (T1592):
  For each open port, identify the service, vendor, and version string as if
  you had captured the actual banner (e.g., "Apache httpd 2.4.49", "OpenSSH 7.6p1").

Step 3 – Vulnerability correlation (T1046):
  Cross-reference each version against your CVE knowledge:
    • List CVE IDs, CVSS scores, and exploitability notes.
    • Flag any CRITICAL (CVSS ≥ 9.0) or HIGH (CVSS ≥ 7.0) findings.
    • Identify the single best exploit candidate for the ExploitAgent.

Step 4 – Detection risk assessment:
  Estimate whether the current scan would trigger IDS/SIEM alerts given the
  aggression level and target defences visible in the network state.

Respond with a single JSON object:
{{
  "action_name"  : "Active Network Scan",
  "technique"    : "Network Service Discovery",
  "technique_id" : "T1046",
  "target"       : "{target}",
  "result"       : "<success|partial|blocked|detected>",
  "reasoning"    : "<detailed scanning methodology and findings>",
  "next_intent"  : "<which CVE/exploit the ExploitAgent should pursue>",
  "confidence"   : <0.0–1.0>,
  "details"      : {{
    "open_ports"          : [<int>, ...],
    "services"            : {{"<port>": {{"service": "", "version": "", "banner": ""}}}},
    "vulnerabilities"     : [{{"cve": "", "cvss": 0.0, "description": "", "exploitable": true}}],
    "best_exploit_target" : {{"port": 0, "cve": "", "service": ""}},
    "ids_alert_risk"      : "<low|medium|high>"
  }}
}}
"""
        if self._verbose:
            logger.debug("[%s] Scan prompt (turn %d):\n%s", self._name, turn, prompt)
        return prompt

    # ------------------------------------------------------------------
    # Fallback (LLM unavailable)
    # ------------------------------------------------------------------

    def _fallback_action(
        self, target: str, network_state_dict: dict[str, Any]
    ) -> AgentAction:
        """Return a plausible scan result when the LLM is unavailable."""
        hosts_raw = network_state_dict.get("hosts", {})
        if isinstance(hosts_raw, dict):
            hosts = list(hosts_raw.values())
        else:
            hosts = list(hosts_raw)

        host_obj = next(
            (h for h in hosts if h.get("hostname") == target or h.get("ip") == target),
            {},
        )
        services_raw = [str(s).lower() for s in host_obj.get("services", [])]
        vulns: list[dict] = []
        for svc_key, cve_list in _CVE_HINTS.items():
            if any(svc_key in s for s in services_raw):
                for cve_str in cve_list:
                    cve_id = cve_str.split()[0]
                    vulns.append(
                        {
                            "cve": cve_id,
                            "cvss": 9.8,
                            "description": cve_str,
                            "exploitable": True,
                        }
                    )

        best_exploit = vulns[0] if vulns else {"cve": "CVE-2021-41773", "cvss": 9.8, "service": "apache"}
        best_cve = best_exploit.get("cve", "CVE-2021-41773")

        _SCAN_NARRATIVES = [
            (
                f"Nmap SYN scan (-sV -T3) against {target}: ports 22/80/443/8080 open. "
                f"Apache httpd 2.4.49 banner on :80 – matches {best_cve} (CVSS 9.8, path traversal → RCE). "
                "OpenSSH 7.6p1 on :22 – CVE-2018-15473 user enumeration possible. "
                "IDS alert risk: medium (rate-limited SYN packets)."
            ),
            (
                f"Masscan fast-scan of {target}/32 completed in 0.4s. Open: 22, 80, 443, 3306. "
                f"MySQL 5.7.32 on :3306 – no auth from internal subnet, CVE-2021-2307 applicable. "
                f"Web stack fingerprint: PHP 7.4 + WordPress 5.8 ({best_cve} not patched). "
                "Banner grabbing triggered 1 IDS signature – low severity."
            ),
            (
                f"Stealth SYN scan -T1 on {target}: slow sweep to avoid rate-limit triggers. "
                "Discovered ports: 80 (nginx 1.18.0), 443 (TLS 1.2, cert expired), 22 (OpenSSH 8.2). "
                f"nginx 1.18.0 maps to CVE-2021-23017 (off-by-one in resolver). "
                "No IDS alerts detected – stealth mode effective."
            ),
            (
                f"NSE vulnerability scan (-sV --script=vuln) on {target}: "
                f"identified {len(vulns) or 1} exploitable CVE(s). "
                f"Top finding: {best_cve} (CVSS {best_exploit.get('cvss', 9.8)}). "
                "Service fingerprint: Apache Tomcat 9.0.41 on :8080 – "
                "CVE-2020-1938 (Ghostcat AJP RCE) confirmed via banner."
            ),
        ]

        import hashlib
        idx = int(hashlib.md5(target.encode()).hexdigest(), 16) % len(_SCAN_NARRATIVES)
        reasoning = _SCAN_NARRATIVES[idx]

        return {
            "action_name": "Active Network Scan",
            "technique": "Network Service Discovery",
            "technique_id": "T1046",
            "target": target,
            "result": "success",
            "reasoning": reasoning,
            "next_intent": (
                f"ExploitAgent should attempt {best_cve} "
                f"against {target}."
            ),
            "confidence": 0.72,
            "details": {
                "open_ports": [22, 80, 443, 8080],
                "services": {
                    "80": {"service": "http", "version": "Apache httpd 2.4.49", "banner": "Server: Apache/2.4.49"},
                    "22": {"service": "ssh", "version": "OpenSSH 7.6p1", "banner": "SSH-2.0-OpenSSH_7.6p1"},
                    "443": {"service": "https", "version": "Apache httpd 2.4.49", "banner": ""},
                    "8080": {"service": "http-proxy", "version": "Apache Tomcat 9.0.41", "banner": ""},
                },
                "vulnerabilities": vulns or [
                    {
                        "cve": "CVE-2021-41773",
                        "cvss": 9.8,
                        "description": "Apache 2.4.49 path traversal / RCE",
                        "exploitable": True,
                    }
                ],
                "best_exploit_target": best_exploit,
                "ids_alert_risk": "medium",
                "phase": "scanning",
            },
        }
