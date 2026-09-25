"""
AnalyzerAgent — Threat Correlation & Kill-Chain Pattern Analyst.

MITRE D3FEND / NIST CSF defensive coverage:
  DE.AE-2  : Understand the impact of events
  DE.AE-5  : Incident alert thresholds established
  RS.AN-1  : Notifications from detection systems investigated
"""

from __future__ import annotations

import json
import logging
from typing import Any

from agents.base_agent import AgentAction, BaseAgent

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are a senior threat intelligence analyst embedded in the SOC.
Your expertise spans the full Unified Kill Chain and MITRE ATT&CK framework.

Your responsibilities:
- Receive alert feeds from monitoring infrastructure (SIEM, NDR, EDR)
- Correlate disparate events into coherent attack narratives
- Identify the current kill-chain phase (Reconnaissance → Weaponisation → Delivery →
  Exploitation → Installation → Command & Control → Actions on Objectives)
- Produce a structured Threat Assessment Report (TAR) for SOC leadership and IR teams
- Recommend defensive actions ordered by priority and impact

You think like a DFIR investigator: timeline-first, evidence-driven, adversary-emulation aware.
Cite specific ATT&CK (sub-)techniques by T-number in every finding.
Output ONLY valid JSON matching the requested schema."""


class AnalyzerAgent(BaseAgent):
    """
    Correlates alert history with current events, infers the attacker's kill-chain
    phase, and recommends prioritised defensive countermeasures.
    """

    description: str = (
        "SOC threat correlation analyst. Maps alert streams to kill-chain phases, "
        "builds attack timelines, and recommends prioritised defensive actions."
    )

    def __init__(self, name: str, llm_client, config: dict) -> None:
        super().__init__(name=name, team="blue", llm_client=llm_client, config=config)

    mitre_techniques: list[str] = ["DE.AE-2", "DE.AE-5", "RS.AN-1"]

    # Kill-chain phase ordering for escalation logic
    _KILL_CHAIN_PHASES: list[str] = [
        "reconnaissance",
        "weaponisation",
        "delivery",
        "exploitation",
        "installation",
        "command_and_control",
        "actions_on_objectives",
    ]

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
        Correlate alert history and current network events into a cohesive
        threat assessment, identifying the current kill-chain phase and
        recommended defensive actions.
        """
        # Collect all blue-team alert details from history
        alert_history = [
            entry.get("details", {})
            for entry in history
            if entry.get("agent_team") == "blue"
        ]

        # Latest red-team technique for direct correlation
        red_actions = [e for e in history if e.get("agent_team") == "red"]
        last_red_action = red_actions[-1] if red_actions else {}

        prompt = self._build_analyzer_prompt(
            network_state_dict, history, turn, alert_history, last_red_action
        )

        if self._verbose:
            logger.debug("[%s] Sending correlation prompt (turn %d)", self._name, turn)

        raw_response = await self._llm_client.chat(
            system=_SYSTEM_PROMPT,
            user=prompt,
            temperature=self._temperature,
            max_tokens=self._max_tokens,
        )

        action = self._parse_response(raw_response)

        # Enrich with analyst metadata
        action["details"].setdefault("kill_chain_phases", self._KILL_CHAIN_PHASES)
        action["details"].setdefault("mitre_defend", self.mitre_techniques)
        action["details"].setdefault("correlated_red_technique", last_red_action.get("technique_id"))

        return action

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def _build_analyzer_prompt(
        self,
        network_state_dict: dict[str, Any],
        history: list[dict[str, Any]],
        turn: int,
        alert_history: list[dict[str, Any]],
        last_red_action: dict[str, Any],
    ) -> str:
        network_json = json.dumps(network_state_dict, indent=2, default=str)
        alerts_json = json.dumps(alert_history[-10:], indent=2, default=str)
        red_json = json.dumps(last_red_action, indent=2, default=str)
        history_summary = self._get_history_summary(history, last_n=6)

        return (
            f"## Threat Correlation Task — Turn {turn}\n\n"
            f"### Network state\n```json\n{network_json}\n```\n\n"
            f"### Alert history (last 10 blue-team events)\n"
            f"```json\n{alerts_json}\n```\n\n"
            f"### Latest red-team action\n```json\n{red_json}\n```\n\n"
            f"### Full recent history (all agents)\n{history_summary}\n\n"
            f"### Your task\n"
            f"You are a threat intelligence analyst. Correlate these security events\n"
            f"to identify attack patterns, determine the current kill-chain phase,\n"
            f"and recommend prioritised countermeasures.\n\n"
            f"Return ONLY valid JSON matching this schema:\n"
            f"{{\n"
            f'  "action_name"  : "Threat Correlation Analysis",\n'
            f'  "technique"    : "<primary MITRE technique being countered>",\n'
            f'  "technique_id" : "<T-number>",\n'
            f'  "target"       : "<primary threat target identified>",\n'
            f'  "result"       : "<detected|partial|blocked|success>",\n'
            f'  "reasoning"    : "<narrative: how events correlate into an attack chain>",\n'
            f'  "next_intent"  : "<escalate to FirewallAgent|recommend isolation|continue>",\n'
            f'  "confidence"   : <float 0.0-1.0>,\n'
            f'  "details"      : {{\n'
            f'    "threat_assessment"  : "<high|medium|low>",\n'
            f'    "attack_stage"       : "<kill_chain_phase>",\n'
            f'    "recommended_actions": ["<action 1>", "<action 2>"],\n'
            f'    "correlated_events"  : ["<event 1>", "<event 2>"],\n'
            f'    "ttps_observed"      : ["<T-number>", "<T-number>"]\n'
            f"  }}\n"
            f"}}\n"
        )
