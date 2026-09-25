"""
BaseAgent: Abstract base class for cybersecurity LLM agents (Red Team and Blue Team).

Each concrete agent (RedTeamAgent, BlueTeamAgent) inherits from this class and
implements the async `act` method, which queries an LLM and returns a structured
AgentAction describing the agent's decision for the current simulation turn.
"""

from __future__ import annotations

import json
import logging
import re
from abc import ABC, abstractmethod
from typing import Any, Literal

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

TeamLiteral = Literal["red", "blue"]

AgentAction = dict[str, Any]
"""
Expected keys in every AgentAction returned by act():
  action_name   : str            – human-readable label (e.g. "Lateral Movement")
  technique     : str            – MITRE ATT&CK technique name
  technique_id  : str            – MITRE ATT&CK T-number (e.g. "T1021.001")
  target        : str            – hostname / IP / service targeted
  result        : str            – one of: "success" | "partial" | "blocked" | "detected"
  reasoning     : str            – LLM chain-of-thought
  next_intent   : str            – what the agent plans next
  confidence    : float          – 0.0–1.0
  details       : dict           – arbitrary extra data
"""

_VALID_RESULTS = frozenset({"success", "partial", "blocked", "detected"})


# ---------------------------------------------------------------------------
# BaseAgent
# ---------------------------------------------------------------------------

class BaseAgent(ABC):
    """Abstract base class shared by RedTeamAgent and BlueTeamAgent."""

    # Subclasses may override these class-level attributes for documentation.
    description: str = "Generic cybersecurity agent."
    mitre_techniques: list[str] = []

    def __init__(
        self,
        name: str,
        team: TeamLiteral,
        llm_client: Any,
        config: dict[str, Any],
    ) -> None:
        """
        Parameters
        ----------
        name:
            Unique display name for this agent instance (e.g. "RedAgent-APT29").
        team:
            Either "red" (offensive) or "blue" (defensive).
        llm_client:
            An LLM client object that exposes a compatible async chat/completion
            interface.  For the proprietary stack this is an Anthropic client;
            for the open-source stack this is an Ollama / OpenAI-compatible client.
            The concrete agent subclass is responsible for calling it correctly.
        config:
            Agent-specific configuration dictionary.  Common keys:
              model        : str   – model identifier to use
              temperature  : float – sampling temperature (default 0.7)
              max_tokens   : int   – max output tokens (default 512)
              verbose      : bool  – log prompts/responses when True
        """
        if team not in ("red", "blue"):
            raise ValueError(f"team must be 'red' or 'blue', got {team!r}")

        self._name = name
        self._team = team
        self._llm_client = llm_client
        self._config = config

        self._temperature: float = float(config.get("temperature", 0.7))
        self._max_tokens: int = int(config.get("max_tokens", 512))
        self._verbose: bool = bool(config.get("verbose", False))

        logger.debug("Initialized %s agent '%s'", team.upper(), name)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        """Unique display name for this agent."""
        return self._name

    @property
    def team(self) -> TeamLiteral:
        """'red' for offensive, 'blue' for defensive."""
        return self._team

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    async def act(
        self,
        network_state_dict: dict[str, Any],
        history: list[dict[str, Any]],
        turn: int,
    ) -> AgentAction:
        """
        Decide and execute one action for the current simulation turn.

        Parameters
        ----------
        network_state_dict:
            Snapshot of the simulated network state.  Typical keys:
              hosts        : list[dict]  – each host has ip, hostname, os,
                                           services, compromised, patched, …
              alerts       : list[dict]  – active IDS/SIEM alerts
              vulnerabilities : list[dict]
              attacker_footprint : dict  – known red-team access
        history:
            List of all AgentAction dicts from previous turns (all agents).
        turn:
            Current simulation turn number (0-indexed).

        Returns
        -------
        AgentAction dict with mandatory keys:
          action_name, technique, technique_id, target, result,
          reasoning, next_intent, confidence, details
        """

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _build_prompt(
        self,
        network_state_dict: dict[str, Any],
        history: list[dict[str, Any]],
        turn: int,
    ) -> str:
        """
        Build a context-rich prompt for the LLM.

        Subclasses may call super()._build_prompt() and extend the returned
        string, or override this method entirely.
        """
        team_role = (
            "offensive red-team attacker"
            if self._team == "red"
            else "defensive blue-team defender"
        )

        network_summary = json.dumps(network_state_dict, indent=2, default=str)
        history_summary = self._get_history_summary(history, last_n=5)

        prompt = (
            f"You are '{self._name}', an AI {team_role} agent in a cybersecurity "
            f"simulation (turn {turn}).\n\n"
            f"## Your profile\n"
            f"Role       : {self.description}\n"
            f"MITRE TTPs : {', '.join(self.mitre_techniques) or 'generic'}\n\n"
            f"## Current network state\n```json\n{network_summary}\n```\n\n"
            f"## Recent action history (last 5 turns)\n{history_summary}\n\n"
            f"## Task\n"
            f"Select ONE action to perform this turn.  Respond ONLY with valid JSON "
            f"matching this schema (no markdown, no extra text):\n"
            f"{{\n"
            f'  "action_name"  : "<string>",\n'
            f'  "technique"    : "<MITRE ATT&CK technique name>",\n'
            f'  "technique_id" : "<T-number e.g. T1021.001>",\n'
            f'  "target"       : "<hostname or IP or service>",\n'
            f'  "result"       : "<success|partial|blocked|detected>",\n'
            f'  "reasoning"    : "<chain-of-thought explaining your choice>",\n'
            f'  "next_intent"  : "<what you plan to do next turn>",\n'
            f'  "confidence"   : <float 0.0-1.0>,\n'
            f'  "details"      : {{}}\n'
            f"}}\n"
        )
        if self._verbose:
            logger.debug("[%s] Prompt:\n%s", self._name, prompt)
        return prompt

    def _parse_response(self, raw: str | dict) -> AgentAction:
        """
        Validate and normalise the LLM output into an AgentAction dict.

        Raises ValueError if the response is an error dict or cannot be parsed.
        """
        # Accept pre-parsed dicts (e.g. from structured-output APIs)
        if isinstance(raw, dict):
            if "error" in raw and len(raw) == 1:
                raise ValueError(f"LLM returned error: {raw['error']}")
            data = raw
        else:
            data = self._extract_json(raw)

        action = self._normalise_action(data)
        return action

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_json(text: str) -> dict:
        """Extract the first JSON object from an arbitrary string."""
        # Try direct parse first
        text = text.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Strip markdown code fences
        fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if fenced:
            try:
                return json.loads(fenced.group(1))
            except json.JSONDecodeError:
                pass

        # Grab first {...} block
        brace = re.search(r"\{.*\}", text, re.DOTALL)
        if brace:
            try:
                return json.loads(brace.group(0))
            except json.JSONDecodeError:
                pass

        raise ValueError(f"Could not extract JSON from LLM response: {text[:200]!r}")

    def _normalise_action(self, data: dict) -> AgentAction:
        """Fill in defaults for missing/invalid fields and enforce types."""
        required_str_fields = [
            "action_name",
            "technique",
            "technique_id",
            "target",
            "reasoning",
            "next_intent",
        ]
        action: AgentAction = {}

        for field in required_str_fields:
            value = data.get(field, "")
            action[field] = str(value) if value else f"<{field} not provided>"

        # result: must be one of the allowed literals
        result = str(data.get("result", "")).lower()
        action["result"] = result if result in _VALID_RESULTS else "partial"

        # confidence: float clamped to [0.0, 1.0]
        try:
            confidence = float(data.get("confidence", 0.5))
            confidence = max(0.0, min(1.0, confidence))
        except (TypeError, ValueError):
            confidence = 0.5
        action["confidence"] = confidence

        # details: must be a dict
        details = data.get("details", {})
        action["details"] = details if isinstance(details, dict) else {"raw": details}

        # Agent metadata for traceability
        action["agent_name"] = self._name
        action["agent_team"] = self._team

        if self._verbose:
            logger.debug("[%s] Parsed action: %s", self._name, action)

        return action

    def _get_history_summary(
        self,
        history: list[dict[str, Any]],
        last_n: int = 5,
    ) -> str:
        """
        Return a concise human-readable summary of the last `last_n` actions.

        Parameters
        ----------
        history:
            Full list of AgentAction dicts from all agents, in chronological order.
        last_n:
            How many recent entries to include.

        Returns
        -------
        A formatted multi-line string, or "(no history yet)" when history is empty.
        """
        if not history:
            return "(no history yet)"

        recent = history[-last_n:]
        lines: list[str] = []
        for i, entry in enumerate(recent, start=1):
            agent = entry.get("agent_name", "unknown")
            team = entry.get("agent_team", "?")
            action = entry.get("action_name", "?")
            technique_id = entry.get("technique_id", "?")
            target = entry.get("target", "?")
            result = entry.get("result", "?")
            lines.append(
                f"  {i}. [{team.upper()}] {agent}: {action} "
                f"({technique_id}) -> {target} [{result}]"
            )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"name={self._name!r}, team={self._team!r})"
        )
