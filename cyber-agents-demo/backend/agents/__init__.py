"""Agents package — exports BaseAgent and its type aliases."""

from __future__ import annotations

from agents.base_agent import BaseAgent, AgentAction, TeamLiteral

__all__: list[str] = ["BaseAgent", "AgentAction", "TeamLiteral"]
