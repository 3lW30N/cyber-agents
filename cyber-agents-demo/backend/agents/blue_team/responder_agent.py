"""
ResponderAgent — Incident Response & Host Isolation Specialist.

MITRE D3FEND / NIST CSF defensive coverage:
  RS.RP-1  : Response plan executed during or after a cybersecurity incident
  RS.MI-1  : Incidents contained
  RS.MI-2  : Incidents mitigated
  RS.MI-3  : Newly identified vulnerabilities mitigated or documented as accepted risks
"""

from __future__ import annotations

import json
import logging
from typing import Any

from agents.base_agent import AgentAction, BaseAgent

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are a senior Incident Response (IR) lead with 10+ years of DFIR
experience. You operate according to NIST SP 800-61 (Incident Handling Guide) and
SANS PICERL methodology (Preparation, Identification, Containment, Eradication,
Recovery, Lessons Learned).

Your active mission during a live intrusion:
- Execute the Containment phase: isolate compromised hosts, revoke credentials,
  kill malicious processes
- Coordinate with Firewall and Monitoring teams for network-level containment
- Apply emergency patches or mitigations for actively exploited vulnerabilities
- Preserve forensic artefacts (memory dumps, log captures) before remediation
- Communicate status to CISO and executive team in clear, non-technical terms

Be decisive. Every minute of dwell time increases blast radius. Prioritise by:
  1. Crown-jewel asset protection
  2. Lateral movement prevention
  3. C2 channel disruption
  4. Evidence preservation

Output ONLY valid JSON matching the requested schema."""


class ResponderAgent(BaseAgent):
    """
    Executes incident response playbooks: isolates compromised hosts,
    applies emergency patches, revokes credentials, and tracks containment status.
    """

    description: str = (
        "DFIR Incident Response lead. Executes NIST SP 800-61 containment and "
        "eradication playbooks, isolates compromised hosts, and applies emergency patches."
    )

    def __init__(self, name: str, llm_client, config: dict) -> None:
        super().__init__(name=name, team="blue", llm_client=llm_client, config=config)

    mitre_techniques: list[str] = ["RS.RP-1", "RS.MI-1", "RS.MI-2", "RS.MI-3"]

    # ------------------------------------------------------------------
    # act()
    # ------------------------------------------------------------------

    async def act(
        self,
        network_state_dict: dict[str, Any],
        history: list[dict[str, Any]],
        turn: int,
    ) -> AgentAction:
        """
        Determine which hosts are compromised, apply containment measures,
        and report the containment status to the simulation engine.
        """
        # Identify compromised hosts from network state
        hosts: list[dict[str, Any]] = network_state_dict.get("hosts", [])
        compromised_hosts = [
            h for h in hosts if h.get("compromised", False)
        ]

        # Determine threat level from analyzer output
        analyzer_outputs = [
            e for e in history
            if "threat_assessment" in e.get("details", {})
        ]
        threat_level: str = "high"
        if analyzer_outputs:
            threat_level = analyzer_outputs[-1].get("details", {}).get("threat_assessment", "high")

        # Latest red-team action
        red_actions = [e for e in history if e.get("agent_team") == "red"]
        last_red_action = red_actions[-1] if red_actions else {}

        prompt = self._build_responder_prompt(
            network_state_dict,
            history,
            turn,
            compromised_hosts,
            threat_level,
            last_red_action,
        )

        if self._verbose:
            logger.debug(
                "[%s] Running IR playbook (turn %d, %d compromised hosts, threat=%s)",
                self._name, turn, len(compromised_hosts), threat_level,
            )

        raw_response = await self._llm_client.chat(
            system=_SYSTEM_PROMPT,
            user=prompt,
            temperature=self._temperature,
            max_tokens=self._max_tokens,
        )

        action = self._parse_response(raw_response)

        action["details"].setdefault("mitre_defend", self.mitre_techniques)
        action["details"].setdefault("threat_level_input", threat_level)
        action["details"].setdefault("compromised_count", len(compromised_hosts))

        return action

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def _build_responder_prompt(
        self,
        network_state_dict: dict[str, Any],
        history: list[dict[str, Any]],
        turn: int,
        compromised_hosts: list[dict[str, Any]],
        threat_level: str,
        last_red_action: dict[str, Any],
    ) -> str:
        network_json = json.dumps(network_state_dict, indent=2, default=str)
        compromised_json = json.dumps(compromised_hosts, indent=2, default=str)
        red_json = json.dumps(last_red_action, indent=2, default=str)
        history_summary = self._get_history_summary(history, last_n=6)

        return (
            f"## Incident Response Activation — Turn {turn}\n\n"
            f"### Declared threat level: {threat_level.upper()}\n\n"
            f"### Network state\n```json\n{network_json}\n```\n\n"
            f"### Compromised hosts requiring containment\n"
            f"```json\n{compromised_json}\n```\n\n"
            f"### Active red-team technique\n```json\n{red_json}\n```\n\n"
            f"### Recent incident timeline\n{history_summary}\n\n"
            f"### Your task\n"
            f"You are an incident responder. Contain the breach by isolating\n"
            f"compromised systems, revoking attacker credentials, killing malicious\n"
            f"processes, and applying emergency patches. Follow NIST SP 800-61.\n\n"
            f"Return ONLY valid JSON matching this schema:\n"
            f"{{\n"
            f'  "action_name"  : "Incident Response — Containment",\n'
            f'  "technique"    : "<primary defensive technique applied>",\n'
            f'  "technique_id" : "<MITRE D3FEND or ATT&CK T-number>",\n'
            f'  "target"       : "<primary host or group isolated>",\n'
            f'  "result"       : "<blocked|partial|detected|success>",\n'
            f'  "reasoning"    : "<IR decision rationale with kill-chain context>",\n'
            f'  "next_intent"  : "<eradication|recovery|escalate|forensics>",\n'
            f'  "confidence"   : <float 0.0-1.0>,\n'
            f'  "details"      : {{\n'
            f'    "isolated_hosts"       : ["<hostname>"],\n'
            f'    "emergency_patches"    : ["<CVE-XXXX-YYYY on hostname>"],\n'
            f'    "revoked_credentials" : ["<user@host>"],\n'
            f'    "containment_status"  : "<contained|partial|failed>",\n'
            f'    "forensic_artefacts"  : ["<memory dump>", "<log capture>"],\n'
            f'    "ciso_summary"        : "<1-sentence executive summary>"\n'
            f"  }}\n"
            f"}}\n"
        )
