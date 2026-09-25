"""
FirewallAgent — Dynamic Firewall Rule Engine.

MITRE D3FEND / NIST CSF defensive coverage:
  PR.AC-5  : Network integrity protected (network segregation, network segmentation)
  PR.PT-3  : Principle of least functionality applied (e.g. certain ports blocked)
  DE.CM-7  : Monitoring for unauthorised connections
"""

from __future__ import annotations

import json
import logging
from typing import Any

from agents.base_agent import AgentAction, BaseAgent

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are a senior network security engineer and firewall architect
operating under active incident response conditions.

Your mandate:
- Receive threat intelligence from the SOC Analyzer and translate it into precise,
  actionable firewall rules (iptables / pf / AWS Security Group / Palo Alto style)
- Apply the principle of least privilege: block only what is necessary; avoid
  collateral disruption to legitimate traffic
- Prioritise rules that stop ongoing lateral movement and C2 beaconing
- Document every rule with: rationale, ATT&CK technique blocked, TTL (temporary/permanent),
  and rollback procedure
- Validate rules for conflicts and ordering before deployment

Think like a firewall engineer who must justify every ACE to the CISO within the hour.
Output ONLY valid JSON matching the requested schema."""


class FirewallAgent(BaseAgent):
    """
    Translates threat intelligence into concrete firewall rules that block
    active attack techniques while minimising disruption to legitimate traffic.
    """

    description: str = (
        "Network security firewall engineer. Generates, validates, and deploys "
        "dynamic ACL/firewall rules to block active attack techniques in real time."
    )

    def __init__(self, name: str, llm_client, config: dict) -> None:
        super().__init__(name=name, team="blue", llm_client=llm_client, config=config)

    mitre_techniques: list[str] = ["PR.AC-5", "PR.PT-3", "DE.CM-7"]

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
        Based on the latest analyzer output and network state, generate
        a set of firewall rules to contain the active threat.
        """
        # Get the most recent AnalyzerAgent output for context
        analyzer_outputs = [
            entry for entry in history
            if entry.get("agent_name", "").lower().startswith("analyzer")
            or "correlation" in entry.get("action_name", "").lower()
        ]
        last_analyzer = analyzer_outputs[-1] if analyzer_outputs else {}

        # Get the last red-team action for direct technique blocking
        red_actions = [e for e in history if e.get("agent_team") == "red"]
        last_red_action = red_actions[-1] if red_actions else {}

        prompt = self._build_firewall_prompt(
            network_state_dict, history, turn, last_analyzer, last_red_action
        )

        if self._verbose:
            logger.debug("[%s] Generating firewall rules (turn %d)", self._name, turn)

        raw_response = await self._llm_client.chat(
            system=_SYSTEM_PROMPT,
            user=prompt,
            temperature=self._temperature,
            max_tokens=self._max_tokens,
        )

        action = self._parse_response(raw_response)

        action["details"].setdefault("mitre_defend", self.mitre_techniques)
        action["details"].setdefault("blocked_red_technique", last_red_action.get("technique_id"))

        return action

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def _build_firewall_prompt(
        self,
        network_state_dict: dict[str, Any],
        history: list[dict[str, Any]],
        turn: int,
        last_analyzer: dict[str, Any],
        last_red_action: dict[str, Any],
    ) -> str:
        network_json = json.dumps(network_state_dict, indent=2, default=str)
        analyzer_json = json.dumps(last_analyzer, indent=2, default=str)
        red_json = json.dumps(last_red_action, indent=2, default=str)
        history_summary = self._get_history_summary(history, last_n=5)

        return (
            f"## Firewall Rule Generation — Turn {turn}\n\n"
            f"### Network state\n```json\n{network_json}\n```\n\n"
            f"### Threat analysis from AnalyzerAgent\n```json\n{analyzer_json}\n```\n\n"
            f"### Active red-team technique to block\n```json\n{red_json}\n```\n\n"
            f"### Recent action history\n{history_summary}\n\n"
            f"### Your task\n"
            f"You are a network security engineer. Based on detected threats,\n"
            f"write firewall rules to block the attack while preserving\n"
            f"legitimate traffic flows. Justify each rule with ATT&CK references.\n\n"
            f"Return ONLY valid JSON matching this schema:\n"
            f"{{\n"
            f'  "action_name"  : "Firewall Rule Deployment",\n'
            f'  "technique"    : "<technique being blocked>",\n'
            f'  "technique_id" : "<T-number>",\n'
            f'  "target"       : "<network segment or host protected>",\n'
            f'  "result"       : "<blocked|partial|detected|success>",\n'
            f'  "reasoning"    : "<rationale: why these rules stop the attack>",\n'
            f'  "next_intent"  : "<monitor effectiveness|escalate to responder|maintain>",\n'
            f'  "confidence"   : <float 0.0-1.0>,\n'
            f'  "details"      : {{\n'
            f'    "new_rules": [\n'
            f'      {{\n'
            f'        "rule_type"   : "<ACL|iptables|security_group|pf>",\n'
            f'        "source"      : "<IP/CIDR or any>",\n'
            f'        "destination" : "<IP/CIDR or any>",\n'
            f'        "port"        : "<port/range or any>",\n'
            f'        "protocol"    : "<tcp|udp|icmp|any>",\n'
            f'        "action"      : "<drop|reject|log>",\n'
            f'        "rationale"   : "<ATT&CK technique blocked>",\n'
            f'        "ttl"         : "<temporary|permanent>"\n'
            f"      }}\n"
            f"    ],\n"
            f'    "blocked_techniques" : ["<T-number>"],\n'
            f'    "rollback_procedure" : "<how to revert if false positive>"\n'
            f"  }}\n"
            f"}}\n"
        )
