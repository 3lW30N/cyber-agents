"""
Blue Team agents package.

Exports all five defensive agents for use in the simulation engine.

Agent pipeline (typical execution order per turn):
  1. MonitorAgent      — detects events and raises alerts
  2. ThreatIntelAgent  — enriches IOCs and attributes the attack
  3. AnalyzerAgent     — correlates alerts into a kill-chain narrative
  4. FirewallAgent     — deploys network-level blocking rules
  5. ResponderAgent    — isolates hosts and applies emergency patches
"""

from agents.blue_team.analyzer_agent import AnalyzerAgent
from agents.blue_team.firewall_agent import FirewallAgent
from agents.blue_team.monitor_agent import MonitorAgent
from agents.blue_team.responder_agent import ResponderAgent
from agents.blue_team.threat_intel_agent import ThreatIntelAgent

__all__ = [
    "MonitorAgent",
    "ThreatIntelAgent",
    "AnalyzerAgent",
    "FirewallAgent",
    "ResponderAgent",
]

# Ordered pipeline for the simulation engine
BLUE_TEAM_PIPELINE: list[str] = [
    "MonitorAgent",
    "ThreatIntelAgent",
    "AnalyzerAgent",
    "FirewallAgent",
    "ResponderAgent",
]
