"""
MonitorAgent — SOC Network Traffic Monitor & Anomaly Detector.

MITRE D3FEND / NIST CSF defensive coverage:
  DE.CM-1  : Network Communications
  DE.CM-7  : Monitoring for unauthorised personnel / connections / devices / software
  DE.AE-3  : Event data aggregated and correlated from multiple sources
"""

from __future__ import annotations

import json
import logging
from typing import Any

from agents.base_agent import AgentAction, BaseAgent

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are an elite SOC Tier-3 analyst responsible for continuous
network traffic monitoring and real-time anomaly detection. Your job is to:

- Correlate raw network events against known Indicators of Compromise (IOCs)
- Identify deviations from established baselines using statistical and behavioral analysis
- Map suspicious activity to MITRE ATT&CK techniques (recon, initial access, lateral movement, C2, exfiltration)
- Produce actionable alerts with CVSS-equivalent confidence scores

Operate with the precision of a SIEM platform (Splunk / Elastic SIEM). Every alert
must include:
  • Source / destination IPs, ports, protocols
  • The ATT&CK technique suspected (with T-number)
  • Confidence level and supporting evidence
  • Suggested triage action for downstream analysts

Be methodical, terse, and data-driven. Avoid speculation without supporting evidence.
Format your final decision as valid JSON only — no markdown, no preamble."""


class MonitorAgent(BaseAgent):
    """
    Continuously monitors simulated network traffic, computes anomaly scores,
    and raises structured alerts when suspicious patterns exceed the configured
    detection sensitivity threshold.
    """

    description: str = (
        "SOC Tier-3 network traffic monitor. Detects anomalies, maps events to "
        "MITRE ATT&CK techniques, and raises alerts for downstream triage."
    )

    def __init__(self, name: str, llm_client, config: dict) -> None:
        super().__init__(name=name, team="blue", llm_client=llm_client, config=config)

    mitre_techniques: list[str] = ["DE.CM-1", "DE.CM-7", "DE.AE-3"]

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
        Analyse the current network state and the most recent red-team action,
        then produce a structured monitoring report.

        The config key ``detection_sensitivity`` (float, 0.0–1.0, default 0.6)
        controls the alert threshold: values closer to 1.0 raise only high-confidence
        alerts; values closer to 0.0 generate verbose / noisy alerts.
        """
        sensitivity: float = float(self._config.get("detection_sensitivity", 0.6))

        # Extract the most recent red-team action from history for direct correlation
        red_actions = [
            entry for entry in history if entry.get("agent_team") == "red"
        ]
        last_red_action: dict[str, Any] = red_actions[-1] if red_actions else {}

        prompt = self._build_monitor_prompt(
            network_state_dict, history, turn, last_red_action, sensitivity
        )

        if self._verbose:
            logger.debug("[%s] Sending monitoring prompt (turn %d)", self._name, turn)

        raw_response = await self._llm_client.chat(
            system=_SYSTEM_PROMPT,
            user=prompt,
            temperature=self._temperature,
            max_tokens=self._max_tokens,
        )

        action = self._parse_response(raw_response)

        # Inject blue-team specific keys into details
        action["details"].setdefault("sensitivity_threshold", sensitivity)
        action["details"].setdefault("red_action_correlated", last_red_action.get("technique_id", "none"))
        action["details"].setdefault("mitre_defend", self.mitre_techniques)

        return action

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def _build_monitor_prompt(
        self,
        network_state_dict: dict[str, Any],
        history: list[dict[str, Any]],
        turn: int,
        last_red_action: dict[str, Any],
        sensitivity: float,
    ) -> str:
        network_json = json.dumps(network_state_dict, indent=2, default=str)
        history_summary = self._get_history_summary(history, last_n=5)
        red_action_json = json.dumps(last_red_action, indent=2, default=str)

        return (
            f"## Simulation context — Turn {turn}\n\n"
            f"### Detection sensitivity: {sensitivity:.2f} "
            f"(raise alerts only when confidence >= {sensitivity:.2f})\n\n"
            f"### Network state snapshot\n```json\n{network_json}\n```\n\n"
            f"### Most recent red-team action (to correlate against)\n"
            f"```json\n{red_action_json}\n```\n\n"
            f"### Recent action history (all agents, last 5 turns)\n"
            f"{history_summary}\n\n"
            f"### Your task\n"
            f"You are monitoring network traffic. Analyse these events for IOCs.\n"
            f"Identify any indicators of compromise, map them to MITRE ATT&CK techniques,\n"
            f"and produce a structured detection report.\n\n"
            f"Return ONLY valid JSON with this exact schema:\n"
            f"{{\n"
            f'  "action_name"  : "Network Traffic Analysis",\n'
            f'  "technique"    : "<MITRE ATT&CK technique name detected>",\n'
            f'  "technique_id" : "<T-number>",\n'
            f'  "target"       : "<monitored host, subnet, or service>",\n'
            f'  "result"       : "<detected|partial|blocked|success>",\n'
            f'  "reasoning"    : "<chain-of-thought: what traffic pattern raised the alert>",\n'
            f'  "next_intent"  : "<hand-off to AnalyzerAgent|escalate|continue monitoring>",\n'
            f'  "confidence"   : <float {sensitivity:.2f}-1.0>,\n'
            f'  "details"      : {{\n'
            f'    "alerts"             : ["<alert 1>", "<alert 2>"],\n'
            f'    "detected_techniques": ["<T-number>"],\n'
            f'    "confidence_scores"  : {{"<T-number>": <float>}},\n'
            f'    "iocs"               : ["<IP>", "<hash>", "<domain>"],\n'
            f'    "severity"           : "<critical|high|medium|low>"\n'
            f"  }}\n"
            f"}}\n"
        )
