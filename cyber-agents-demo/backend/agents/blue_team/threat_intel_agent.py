"""
ThreatIntelAgent — IOC Enrichment & Threat Intelligence Feed Manager.

MITRE D3FEND / NIST CSF defensive coverage:
  ID.RA-3  : Threats, vulnerabilities, likelihoods, and impacts are used to determine risk
  DE.AE-2  : Understand the impact of events (enriched with external TI)
  PR.IP-8  : Effectiveness of protection technologies shared with appropriate parties
"""

from __future__ import annotations

import json
import logging
from typing import Any

from agents.base_agent import AgentAction, BaseAgent

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are a Cyber Threat Intelligence (CTI) analyst specialising in
strategic and tactical threat intelligence production. You operate at the intersection
of the Diamond Model of Intrusion Analysis and MITRE ATT&CK.

Your responsibilities:
- Enrich raw Indicators of Compromise (IOCs) with threat actor attribution, campaign
  context, and historical TTP patterns
- Profile adversaries using the Diamond Model (Adversary, Infrastructure, Capability, Victim)
- Update detection signatures (YARA, Sigma, Snort) based on newly observed TTPs
- Assess the threat level (1–10) and communicate it with supporting evidence
- Maintain a tactical threat actor playbook updated in real time

You reference threat intelligence sources: MISP, STIX/TAXII, VirusTotal, Shodan,
AlienVault OTX, and government advisories (CISA KEV, MS-ISAC).

Be analytical, precise, and intelligence-led. Every claim must be backed by an observable.
Output ONLY valid JSON matching the requested schema."""


class ThreatIntelAgent(BaseAgent):
    """
    Enriches IOCs with threat actor context, produces adversary profiles,
    updates detection signatures, and maintains a real-time threat level score.
    """

    description: str = (
        "CTI analyst. Enriches IOCs, attributes attacks to threat actor groups, "
        "updates YARA/Sigma signatures, and maintains a live threat-level score (1–10)."
    )

    def __init__(self, name: str, llm_client, config: dict) -> None:
        super().__init__(name=name, team="blue", llm_client=llm_client, config=config)

    mitre_techniques: list[str] = ["ID.RA-3", "DE.AE-2", "PR.IP-8"]

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
        Collect raw IOCs from the network state and alert history, enrich them
        with threat actor attribution, and update detection signatures.
        """
        # Gather raw IOCs from all blue-team alert details
        raw_iocs: list[str] = []
        for entry in history:
            if entry.get("agent_team") == "blue":
                iocs = entry.get("details", {}).get("iocs", [])
                raw_iocs.extend(iocs)

        # Collect red-team techniques observed so far
        red_techniques = list({
            e.get("technique_id", "")
            for e in history
            if e.get("agent_team") == "red" and e.get("technique_id")
        })

        # Most recent red-team action for direct enrichment
        red_actions = [e for e in history if e.get("agent_team") == "red"]
        last_red_action = red_actions[-1] if red_actions else {}

        prompt = self._build_intel_prompt(
            network_state_dict,
            history,
            turn,
            raw_iocs,
            red_techniques,
            last_red_action,
        )

        if self._verbose:
            logger.debug(
                "[%s] Enriching %d IOCs, %d red techniques (turn %d)",
                self._name, len(raw_iocs), len(red_techniques), turn,
            )

        raw_response = await self._llm_client.chat(
            system=_SYSTEM_PROMPT,
            user=prompt,
            temperature=self._temperature,
            max_tokens=self._max_tokens,
        )

        action = self._parse_response(raw_response)

        action["details"].setdefault("mitre_defend", self.mitre_techniques)
        action["details"].setdefault("raw_iocs_input", raw_iocs[:20])  # cap for logging
        action["details"].setdefault("red_techniques_observed", red_techniques)

        return action

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def _build_intel_prompt(
        self,
        network_state_dict: dict[str, Any],
        history: list[dict[str, Any]],
        turn: int,
        raw_iocs: list[str],
        red_techniques: list[str],
        last_red_action: dict[str, Any],
    ) -> str:
        network_json = json.dumps(network_state_dict, indent=2, default=str)
        iocs_json = json.dumps(list(set(raw_iocs))[:30], indent=2, default=str)
        techniques_json = json.dumps(red_techniques, indent=2, default=str)
        red_json = json.dumps(last_red_action, indent=2, default=str)
        history_summary = self._get_history_summary(history, last_n=5)

        return (
            f"## Threat Intelligence Enrichment — Turn {turn}\n\n"
            f"### Network state\n```json\n{network_json}\n```\n\n"
            f"### Raw IOCs to enrich\n```json\n{iocs_json}\n```\n\n"
            f"### Red-team ATT&CK techniques observed across this simulation\n"
            f"```json\n{techniques_json}\n```\n\n"
            f"### Latest red-team action\n```json\n{red_json}\n```\n\n"
            f"### Simulation timeline\n{history_summary}\n\n"
            f"### Your task\n"
            f"You are a cyber threat intelligence analyst. Enrich these IOCs,\n"
            f"attribute the attack to a known or hypothetical threat actor,\n"
            f"update detection signatures (YARA/Sigma), and assign a threat level\n"
            f"score from 1 (negligible) to 10 (nation-state / APT critical).\n\n"
            f"Return ONLY valid JSON matching this schema:\n"
            f"{{\n"
            f'  "action_name"  : "Threat Intelligence Enrichment",\n'
            f'  "technique"    : "<primary technique attributed to threat actor>",\n'
            f'  "technique_id" : "<T-number>",\n'
            f'  "target"       : "<primary victim asset or sector>",\n'
            f'  "result"       : "<detected|partial|blocked|success>",\n'
            f'  "reasoning"    : "<attribution logic: TTPs + Diamond Model analysis>",\n'
            f'  "next_intent"  : "<share signatures with blue team|escalate|monitor>",\n'
            f'  "confidence"   : <float 0.0-1.0>,\n'
            f'  "details"      : {{\n'
            f'    "iocs": [\n'
            f'      {{\n'
            f'        "indicator"   : "<IP/hash/domain>",\n'
            f'        "type"        : "<ip|domain|file_hash|url>",\n'
            f'        "enrichment"  : "<VirusTotal/MISP context>",\n'
            f'        "malicious"   : <true|false>\n'
            f"      }}\n"
            f"    ],\n"
            f'    "threat_actor_profile": {{\n'
            f'      "name"         : "<APT group or hypothetical actor>",\n'
            f'      "motivation"   : "<espionage|financial|disruption>",\n'
            f'      "sophistication": "<nation-state|criminal|hacktivist>",\n'
            f'      "ttps"         : ["<T-number>"]\n'
            f"    }},\n"
            f'    "updated_signatures": [\n'
            f'      {{\n'
            f'        "type"    : "<YARA|Sigma|Snort>",\n'
            f'        "name"    : "<rule name>",\n'
            f'        "pattern" : "<brief rule pattern>"\n'
            f"      }}\n"
            f"    ],\n"
            f'    "threat_level": <integer 1-10>\n'
            f"  }}\n"
            f"}}\n"
        )
