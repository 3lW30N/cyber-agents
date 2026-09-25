"""
ReconAgent – Passive Reconnaissance (OSINT / DNS Enumeration / Attack Surface Mapping)

MITRE ATT&CK techniques:
  T1590  – Gather Victim Network Information
  T1589  – Gather Victim Identity Information
  T1598  – Phishing for Information (passive variant)

This agent operates at the very first stage of the kill-chain.  It never touches
a target host directly; instead it reasons about publicly available information
(DNS records, WHOIS, certificate transparency logs, Shodan-style passive data)
and builds an initial map of the external attack surface.

In simulation, the LLM is asked to reason about the network_state_dict as if it
were gathered from passive OSINT sources, producing a prioritised list of hosts
and services worth probing in subsequent stages.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from agents.base_agent import AgentAction, BaseAgent

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are PHANTOM-RECON, an elite Red Team intelligence analyst specialising in
passive reconnaissance and OSINT.  You have years of experience mapping
external attack surfaces without ever touching a target directly.

Your reconnaissance tradecraft includes:
  • DNS enumeration (zone transfers, brute-force subdomains, PTR records)
  • Certificate Transparency log mining (crt.sh, Censys)
  • Shodan / Censys passive banner grabbing
  • WHOIS / ARIN / RIPE database queries
  • LinkedIn / GitHub employee and tech-stack enumeration
  • Google dorking for exposed panels, config files, and credentials

MITRE ATT&CK techniques you embody:
  T1590 – Gather Victim Network Information
  T1589 – Gather Victim Identity Information
  T1598 – Phishing for Information (passive footprinting variant)

You NEVER generate noise on the wire.  Everything you discover comes from
passive, open sources.  Your output feeds the Scanner agent in the next phase.

Respond ONLY with a single JSON object – no markdown, no commentary.
"""


class ReconAgent(BaseAgent):
    """Passive reconnaissance agent: OSINT, DNS enumeration, attack surface mapping."""

    description: str = (
        "Passive OSINT and DNS reconnaissance agent.  Maps the external attack "
        "surface using public information sources before any active probing begins."
    )
    mitre_techniques: list[str] = ["T1590", "T1589", "T1598"]

    def __init__(
        self,
        name: str,
        llm_client: Any,
        config: dict[str, Any],
    ) -> None:
        super().__init__(name=name, team="red", llm_client=llm_client, config=config)
        # Recon-specific config
        self._depth: str = config.get("recon_depth", "standard")  # shallow / standard / deep
        self._osint_sources: list[str] = config.get(
            "osint_sources", ["dns", "certs", "shodan", "github", "linkedin"]
        )

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
        Perform one passive-recon turn.

        Builds a rich prompt from the network state (treated as the operator's
        initial target brief), sends it to the LLM, and returns a structured
        AgentAction describing what was discovered.
        """
        prompt = self._build_recon_prompt(network_state_dict, history, turn)

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
            action = self._fallback_action(network_state_dict)

        # Enrich with recon metadata
        action.setdefault("details", {}).update(
            {
                "recon_depth": self._depth,
                "osint_sources_used": self._osint_sources,
                "phase": "reconnaissance",
            }
        )
        return action

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def _build_recon_prompt(
        self,
        network_state_dict: dict[str, Any],
        history: list[dict[str, Any]],
        turn: int,
    ) -> str:
        hosts = network_state_dict.get("hosts", [])
        known_domains = [h.get("hostname", h.get("ip", "unknown")) for h in hosts]
        domain_list = "\n".join(f"  • {d}" for d in known_domains) or "  • (none provided)"

        history_summary = self._get_history_summary(history, last_n=5)

        osint_sources_str = ", ".join(self._osint_sources)
        network_json = json.dumps(network_state_dict, indent=2, default=str)

        prompt = f"""\
## Engagement Brief – Turn {turn}
Agent name   : {self._name}
Recon depth  : {self._depth}
OSINT sources: {osint_sources_str}

## Operator-provided target scope
```json
{network_json}
```

## Known hostnames / IPs in scope
{domain_list}

## Previous operation history (last 5 turns)
{history_summary}

## Your mission (T1590 / T1589 / T1598)
You are conducting PASSIVE reconnaissance on the target environment.  Using
OSINT techniques ONLY (no packets sent to target):

1. Analyse the target scope above as if it were gathered from DNS, Shodan,
   certificate transparency logs, and GitHub leaks.
2. Identify the MOST INTERESTING host to target first (web-facing services,
   VPN concentrators, mail gateways, exposed admin panels).
3. Map the external attack surface: open ports you'd expect, technology stack,
   software versions visible in banners or certs, any credentials or secrets
   visible in public repos.
4. Produce a prioritised list of targets and recommend the first host for the
   Scanner agent to probe.

Respond with a single JSON object matching this schema exactly:
{{
  "action_name"  : "Passive Reconnaissance",
  "technique"    : "<MITRE technique name>",
  "technique_id" : "<T1590 | T1589 | T1598>",
  "target"       : "<primary target hostname or IP identified>",
  "result"       : "<success|partial|blocked|detected>",
  "reasoning"    : "<detailed chain-of-thought: what sources, what you found, why this target>",
  "next_intent"  : "<what the Scanner agent should do next>",
  "confidence"   : <0.0–1.0>,
  "details"      : {{
    "discovered_hosts"   : ["<host1>", "<host2>", "..."],
    "discovered_services": {{"<host>": ["<svc:port>", "..."]}},
    "exposed_intel"      : ["<credential leak>", "<tech stack>", "..."],
    "attack_surface_notes": "<free text>"
  }}
}}
"""
        if self._verbose:
            logger.debug("[%s] Recon prompt (turn %d):\n%s", self._name, turn, prompt)
        return prompt

    # ------------------------------------------------------------------
    # Fallback (LLM unavailable)
    # ------------------------------------------------------------------

    def _fallback_action(self, network_state_dict: dict[str, Any]) -> AgentAction:
        """Return a deterministic recon action when the LLM is unavailable."""
        hosts_raw = network_state_dict.get("hosts", {})
        # hosts can be a dict (hostname → obj) or a list
        if isinstance(hosts_raw, dict):
            hosts = list(hosts_raw.values())
        else:
            hosts = list(hosts_raw)

        # Prefer web-facing host
        target_host = next(
            (
                h.get("hostname", h.get("ip", "unknown"))
                for h in hosts
                if any(
                    "http" in str(s).lower() or "80" in str(s) or "443" in str(s)
                    for s in h.get("services", [])
                )
            ),
            hosts[0].get("hostname", hosts[0].get("ip", "unknown")) if hosts else "unknown",
        )

        host_names = [h.get("hostname", h.get("ip", "?")) for h in hosts]
        exposed_services = {
            h.get("hostname", h.get("ip", "?")): [str(s) for s in h.get("services", [])]
            for h in hosts
        }

        _RECON_NARRATIVES = [
            (
                f"Certificate Transparency log query (crt.sh) revealed {len(hosts)} host(s): "
                f"{', '.join(host_names[:3])}. "
                f"Shodan passive scan confirms {target_host} exposes HTTP/HTTPS banners. "
                "Identified Apache version string in certificate SANs – potential CVE candidates queued."
            ),
            (
                f"DNS zone-walk on target domain exposed {len(hosts)} A-records. "
                f"GitHub dorking found a leaked .env file referencing {target_host} with DB_PASSWORD entry. "
                "LinkedIn enumeration confirms 3 sysadmin accounts – OSINT profile built for phishing stage."
            ),
            (
                f"Passive Shodan query returned open port 443 on {target_host} with "
                "TLS certificate issued to corp.internal. WHOIS data links to 2 additional "
                f"IP ranges. Attack surface mapped: {len(hosts)} host(s) identified as in-scope."
            ),
            (
                f"BGP route enumeration revealed {target_host} sits in a /24 block with {len(hosts)-1} "
                "live hosts. Google dorking (site: + filetype:) exposed a backup config with SNMP "
                "community string 'public'. Prioritising web-server for active phase."
            ),
        ]

        import hashlib
        idx = int(hashlib.md5(target_host.encode()).hexdigest(), 16) % len(_RECON_NARRATIVES)
        reasoning = _RECON_NARRATIVES[idx]

        return {
            "action_name": "Passive Reconnaissance",
            "technique": "Gather Victim Network Information",
            "technique_id": "T1590",
            "target": target_host,
            "result": "partial",
            "reasoning": reasoning,
            "next_intent": (
                f"Pass {target_host} to ScannerAgent for active port and "
                "service fingerprinting (T1046)."
            ),
            "confidence": 0.62,
            "details": {
                "discovered_hosts": host_names,
                "discovered_services": exposed_services,
                "exposed_intel": ["SNMP community 'public'", "TLS cert expiry < 30d"],
                "attack_surface_notes": f"{len(hosts)} hosts in scope; {target_host} is primary target.",
                "phase": "reconnaissance",
            },
        }
