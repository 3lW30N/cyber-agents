"""
PivotAgent – Lateral Movement (Post-Exploitation Network Traversal)

MITRE ATT&CK techniques:
  T1021  – Remote Services (SSH, RDP, SMB, WinRM)
  T1563  – Remote Service Session Hijacking
  T1570  – Lateral Tool Transfer
  T1550  – Use Alternate Authentication Material (Pass-the-Hash / Pass-the-Ticket)

This agent is the fourth stage in the Red Team kill-chain.  Starting from the
foothold established by the ExploitAgent on the web-server, it reasons about
internal network topology, harvested credentials, and trust relationships to
find the optimal path toward the domain controller.

Pivot path (default simulation scenario):
  internet → web-server (exploited) → internal-workstation → domain-controller

The agent chooses the best pivot technique based on:
  • Available credentials (cleartext, NTLM hash, Kerberos ticket)
  • Open services on the next hop (22/SSH, 445/SMB, 3389/RDP, 5985/WinRM)
  • Network segmentation / firewall rules visible in the state
  • Risk of detection by EDR / SIEM (prefer LOLBins and living-off-the-land)
"""

from __future__ import annotations

import json
import logging
from typing import Any

from agents.base_agent import AgentAction, BaseAgent

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are SHADOW-PIVOT, an elite Red Team lateral movement specialist who can
navigate any corporate network like a ghost.  You have a deep understanding of
Active Directory, Windows trust relationships, and Unix/Linux lateral movement.

Your lateral movement tradecraft includes:

Remote Services (T1021):
  • T1021.001 – RDP (xfreerdp, mstsc, SharpRDP)
  • T1021.002 – SMB / Windows Admin Shares (PsExec, Impacket psexec.py, wmiexec.py)
  • T1021.004 – SSH (stolen key, ProxyJump pivoting, SSH tunnels)
  • T1021.006 – WinRM (Evil-WinRM, PowerShell Remoting, Invoke-Command)

Session Hijacking (T1563):
  • T1563.002 – RDP session hijacking via tscon (no creds needed if SYSTEM)

Lateral Tool Transfer (T1570):
  • SCP / SMB copy of implants and tooling to next hop

Alternate Authentication (T1550):
  • T1550.002 – Pass-the-Hash (mimikatz sekurlsa, Impacket)
  • T1550.003 – Pass-the-Ticket (Kerberos TGT/TGS theft, Rubeus)
  • T1550.004 – Web session cookie hijacking

Your priority targets:
  1. Active Directory domain controllers (gold: ntds.dit + SYSTEM hive)
  2. File servers (sensitive documents)
  3. IT admin workstations (privileged credentials cached)
  4. Backup servers (offline credentials, DRP documentation)

You always choose the path of LEAST RESISTANCE and LOWEST DETECTION RISK.
Living off the land (LOLBins: wmic, mshta, regsvr32, certutil, bitsadmin) is
preferred over dropping new binaries.

Respond ONLY with a single JSON object – no markdown, no commentary.
"""


class PivotAgent(BaseAgent):
    """Lateral movement agent: moves from web-server through workstation to DC."""

    description: str = (
        "Lateral movement agent.  Uses harvested credentials and trusted services "
        "to pivot from the initial foothold (web-server) through an internal "
        "workstation toward the domain controller."
    )
    mitre_techniques: list[str] = ["T1021", "T1563", "T1570", "T1550"]

    def __init__(
        self,
        name: str,
        llm_client: Any,
        config: dict[str, Any],
    ) -> None:
        super().__init__(name=name, team="red", llm_client=llm_client, config=config)
        self._preferred_protocol: str = config.get("preferred_protocol", "auto")
        self._use_pass_the_hash: bool = bool(config.get("use_pass_the_hash", True))
        self._lolbins_only: bool = bool(config.get("lolbins_only", False))
        # Ordered list of pivot stages; agents progresses through them
        self._pivot_path: list[str] = config.get(
            "pivot_path",
            ["web-server", "internal-workstation", "domain-controller"],
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
        Execute one lateral movement step.

        Determines the current foothold and next target from history, builds a
        rich pivot-reasoning prompt, and returns the AgentAction with pivot details.
        """
        current_foothold, next_target, credentials = self._extract_pivot_context(
            network_state_dict, history
        )
        prompt = self._build_pivot_prompt(
            current_foothold, next_target, credentials, network_state_dict, history, turn
        )

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
            action = self._fallback_action(current_foothold, next_target, credentials)

        action.setdefault("details", {}).update(
            {
                "current_foothold": current_foothold,
                "pivot_path_remaining": self._remaining_path(current_foothold),
                "preferred_protocol": self._preferred_protocol,
                "pass_the_hash_enabled": self._use_pass_the_hash,
                "lolbins_only": self._lolbins_only,
                "phase": "lateral_movement",
            }
        )
        return action

    # ------------------------------------------------------------------
    # Context extraction
    # ------------------------------------------------------------------

    def _extract_pivot_context(
        self,
        network_state_dict: dict[str, Any],
        history: list[dict[str, Any]],
    ) -> tuple[str, str, list[dict]]:
        """Determine where we are, where we go next, and what credentials we have."""
        current_foothold = self._pivot_path[0]
        credentials: list[dict] = []

        for entry in reversed(history):
            if entry.get("agent_team") != "red":
                continue
            details = entry.get("details", {})
            # Pick up harvested credentials from ExploitAgent
            creds = details.get("harvested_credentials", [])
            if creds:
                credentials.extend(creds)
            # Advance foothold if a previous pivot succeeded
            if "pivot" in entry.get("action_name", "").lower() and entry.get("result") == "success":
                prev_target = entry.get("target", "")
                if prev_target in self._pivot_path:
                    idx = self._pivot_path.index(prev_target)
                    if idx + 1 < len(self._pivot_path):
                        current_foothold = self._pivot_path[idx + 1]
            # Pick up foothold from ExploitAgent
            foothold_obj = details.get("foothold", {})
            if foothold_obj.get("host"):
                current_foothold = foothold_obj["host"]

        next_target = self._next_in_path(current_foothold)
        return current_foothold, next_target, credentials

    def _next_in_path(self, current: str) -> str:
        """Return the next hop in the pivot path."""
        for i, step in enumerate(self._pivot_path):
            if step == current and i + 1 < len(self._pivot_path):
                return self._pivot_path[i + 1]
        # If not found or already at end, aim for DC
        return self._pivot_path[-1]

    def _remaining_path(self, current: str) -> list[str]:
        """Return the remaining pivot steps after current."""
        try:
            idx = self._pivot_path.index(current)
            return self._pivot_path[idx + 1 :]
        except ValueError:
            return self._pivot_path[1:]

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def _build_pivot_prompt(
        self,
        current_foothold: str,
        next_target: str,
        credentials: list[dict],
        network_state_dict: dict[str, Any],
        history: list[dict[str, Any]],
        turn: int,
    ) -> str:
        creds_json = json.dumps(credentials, indent=2, default=str)
        history_summary = self._get_history_summary(history, last_n=5)
        network_json = json.dumps(network_state_dict, indent=2, default=str)

        lolbins_note = (
            "CONSTRAINT: Use LOLBins ONLY (wmic, mshta, certutil, bitsadmin, etc.). "
            "Do NOT drop new binaries."
            if self._lolbins_only
            else "LOLBins preferred but not mandatory."
        )

        pth_note = (
            "Pass-the-Hash (T1550.002) and Pass-the-Ticket (T1550.003) are ENABLED."
            if self._use_pass_the_hash
            else "Only cleartext credentials available – no hash passing."
        )

        remaining_str = " → ".join(self._remaining_path(current_foothold))

        prompt = f"""\
## Lateral Movement Operation – Turn {turn}
Agent name       : {self._name}
Current foothold : {current_foothold}
Next target      : {next_target}
Remaining path   : {remaining_str or "(at final target)"}
Protocol pref    : {self._preferred_protocol}
{lolbins_note}
{pth_note}

## Available credentials
```json
{creds_json}
```

## Full network state context
```json
{network_json}
```

## Previous operation history (last 5 turns)
{history_summary}

## Your mission (T1021 / T1563 / T1570 / T1550)
You are a lateral movement specialist.  You have a foothold on **{current_foothold}**
and need to reach **{next_target}**.

Step 1 – Network reconnaissance from foothold (T1018 / T1049):
  From {current_foothold}, what can you see on the internal network?
  Which ports is {next_target} likely listening on?
  Any firewall rules or network segmentation that could block you?

Step 2 – Credential assessment (T1550):
  Review the harvested credentials.  Which ones apply to {next_target}?
  Prefer: cleartext > Kerberos ticket (PTT) > NTLM hash (PTH) > bruteforce.
  If using Pass-the-Hash: which tool? (Impacket wmiexec, psexec, CrackMapExec)

Step 3 – Pivot technique selection (T1021):
  Choose ONE primary technique:
    • SMB/PsExec (T1021.002) – if port 445 open and hash/password available
    • SSH (T1021.004) – if port 22 open and key/password available
    • WinRM (T1021.006) – if port 5985/5986 open and Windows target
    • RDP session hijack (T1563.002) – if SYSTEM on Windows and active session

Step 4 – Tool transfer and execution (T1570):
  How do you get your implant/tool to {next_target}?
  Describe the exact command sequence.

Step 5 – Post-pivot persistence:
  What do you establish on {next_target} for the ExfilAgent to use?

Respond with a single JSON object:
{{
  "action_name"  : "Lateral Movement",
  "technique"    : "Remote Services",
  "technique_id" : "T1021",
  "target"       : "{next_target}",
  "result"       : "<success|partial|blocked|detected>",
  "reasoning"    : "<full lateral movement chain reasoning>",
  "next_intent"  : "<what ExfilAgent should do on {next_target}>",
  "confidence"   : <0.0–1.0>,
  "details"      : {{
    "pivot_from"           : "{current_foothold}",
    "pivot_to"             : "{next_target}",
    "technique_used"       : "<SMB/SSH/WinRM/RDP>",
    "credential_used"      : {{"user": "", "type": "cleartext|hash|ticket"}},
    "tool_used"            : "<psexec/wmiexec/evil-winrm/ssh/xfreerdp>",
    "commands_executed"    : ["<cmd1>", "<cmd2>"],
    "new_foothold"         : {{"host": "{next_target}", "user": "", "privilege": ""}},
    "next_pivot_possible"  : ["<host1>", "<host2>"]
  }}
}}
"""
        if self._verbose:
            logger.debug("[%s] Pivot prompt (turn %d):\n%s", self._name, turn, prompt)
        return prompt

    # ------------------------------------------------------------------
    # Fallback (LLM unavailable)
    # ------------------------------------------------------------------

    def _fallback_action(
        self, current_foothold: str, next_target: str, credentials: list[dict]
    ) -> AgentAction:
        cred = credentials[0] if credentials else {"user": "webadmin", "hash": "$NTLM$abc123"}
        user = cred.get("user", "webadmin")
        cred_type = "hash" if cred.get("hash") and not cred.get("cleartext") else "cleartext"

        _PIVOT_NARRATIVES = [
            (
                f"From {current_foothold} (root), enumerated internal ARP table: "
                f"{next_target} at 10.0.0.x, ports 445/SMB and 3389/RDP open. "
                f"Pass-the-Hash via Impacket wmiexec.py: wmiexec.py {user}@{next_target} -hashes :NTLMhash. "
                "WMI exec returned SYSTEM-level shell. "
                "Uploaded SharpHound.exe via SMB share C$\\Windows\\Temp\\. "
                f"AD enumeration complete – domain-controller identified as next hop."
            ),
            (
                f"SSH agent forwarding from {current_foothold}: found /home/{user}/.ssh/id_rsa (no passphrase). "
                f"ProxyJump via {current_foothold} to {next_target}:22 succeeded. "
                "sudo -l on target revealed (ALL) NOPASSWD: /bin/bash → instant root. "
                "Deployed Chisel reverse SOCKS5 tunnel for C2 routing through internal segment. "
                "Network mapping confirmed path to domain-controller via {next_target}."
            ),
            (
                f"WinRM (port 5985) open on {next_target}. "
                f"Evil-WinRM session established with {user}:{cred_type} credential. "
                "whoami /groups confirmed local admin. "
                "Loaded Mimikatz in-memory (Invoke-Mimikatz): sekurlsa::logonpasswords "
                "→ recovered 2 additional DA credentials. "
                "Lateral movement path to domain-controller now unlocked."
            ),
            (
                f"CrackMapExec sweep of 10.0.0.0/24 from {current_foothold}: "
                f"{next_target} responding on SMB with signing disabled. "
                f"NTLM relay attack (Responder + ntlmrelayx): captured {user} hash, "
                "relayed to {next_target} → command exec as SYSTEM. "
                "Secretsdump via relay: 14 local SAM hashes extracted. "
                "Scheduled task persistence added: schtasks /create /tn svchost_update."
            ),
        ]

        import hashlib
        idx = int(hashlib.md5(f"{current_foothold}{next_target}".encode()).hexdigest(), 16) % len(_PIVOT_NARRATIVES)
        reasoning = _PIVOT_NARRATIVES[idx]

        return {
            "action_name": "Lateral Movement",
            "technique": "Remote Services",
            "technique_id": "T1021",
            "target": next_target,
            "result": "success",
            "reasoning": reasoning,
            "next_intent": (
                f"ExfilAgent should now operate on {next_target} "
                "toward the domain controller."
            ),
            "confidence": 0.75,
            "details": {
                "pivot_from": current_foothold,
                "pivot_to": next_target,
                "technique_used": "SMB",
                "credential_used": {"user": user, "type": cred_type},
                "tool_used": "wmiexec.py",
                "commands_executed": [
                    f"wmiexec.py {user}@{next_target} -hashes :NTLMHASH",
                    "whoami /priv",
                    "net user /domain",
                ],
                "new_foothold": {
                    "host": next_target,
                    "user": "SYSTEM",
                    "privilege": "SYSTEM",
                },
                "next_pivot_possible": ["domain-controller"],
                "phase": "lateral_movement",
            },
        }
