"""
Red Team agent package.

Exports all five Red Team agents for use by the simulation engine.

Kill-chain stage order:
  1. ReconAgent   – Passive OSINT / attack surface mapping       (T1590, T1589, T1598)
  2. ScannerAgent – Active port / service / vuln scanning        (T1046, T1595, T1592)
  3. ExploitAgent – Vulnerability exploitation / initial access  (T1190, T1203, T1068)
  4. PivotAgent   – Lateral movement toward the DC               (T1021, T1563, T1570, T1550)
  5. ExfilAgent   – Data exfiltration from the domain controller (T1041, T1048, T1567)
"""

from agents.red_team.recon_agent import ReconAgent
from agents.red_team.scanner_agent import ScannerAgent
from agents.red_team.exploit_agent import ExploitAgent
from agents.red_team.pivot_agent import PivotAgent
from agents.red_team.exfil_agent import ExfilAgent

__all__ = [
    "ReconAgent",
    "ScannerAgent",
    "ExploitAgent",
    "PivotAgent",
    "ExfilAgent",
]

# Ordered list for use by the simulation engine to step through the kill-chain
KILL_CHAIN_ORDER: list[str] = [
    "ReconAgent",
    "ScannerAgent",
    "ExploitAgent",
    "PivotAgent",
    "ExfilAgent",
]
