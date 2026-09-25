"""
main.py – FastAPI entry point for the Red/Blue Team cybersecurity agent demo.

Provides:
  - REST endpoints for simulation control and configuration
  - Server-Sent Events (SSE) for real-time agent event streaming
  - WebSocket endpoint for bidirectional control
  - Health check endpoint
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

# ---------------------------------------------------------------------------
# Environment & logging
# ---------------------------------------------------------------------------

load_dotenv()

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal imports (after env is loaded)
# ---------------------------------------------------------------------------

from simulation.network_state import NetworkState  # noqa: E402
from llm.gemini_client import GeminiClient  # noqa: E402
from llm.groq_client import GroqClient  # noqa: E402

from agents.red_team.recon_agent import ReconAgent  # noqa: E402
from agents.red_team.scanner_agent import ScannerAgent  # noqa: E402
from agents.red_team.exploit_agent import ExploitAgent  # noqa: E402
from agents.red_team.pivot_agent import PivotAgent  # noqa: E402
from agents.red_team.exfil_agent import ExfilAgent  # noqa: E402

from agents.blue_team.monitor_agent import MonitorAgent  # noqa: E402
from agents.blue_team.analyzer_agent import AnalyzerAgent  # noqa: E402
from agents.blue_team.firewall_agent import FirewallAgent  # noqa: E402
from agents.blue_team.responder_agent import ResponderAgent  # noqa: E402
from agents.blue_team.threat_intel_agent import ThreatIntelAgent  # noqa: E402

# ---------------------------------------------------------------------------
# Global simulation state  (reset-able via /simulation/reset)
# ---------------------------------------------------------------------------

_sim_state: dict[str, Any] = {
    "network": None,           # NetworkState instance
    "history": [],             # list[AgentAction]
    "turn": 0,
    "running": False,
    "red_agents": [],
    "blue_agents": [],
    "config": {
        "stack": "proprietary",   # "proprietary" | "opensource"
        "red_model": os.getenv("RED_MODEL", "gemini-3.8-flash"),
        "blue_model": os.getenv("BLUE_MODEL", "gemini-3.8-flash"),
        "temperature": 0.7,
        "max_tokens": 512,
        "turn_delay": 1.5,        # seconds between turns
        "max_turns": 20,
        "red_agents_enabled": ["recon", "scanner", "exploit", "pivot", "exfil"],
        "blue_agents_enabled": ["monitor", "analyzer", "firewall", "responder", "threat_intel"],
        "verbose": False,
    },
}

# SSE / WebSocket broadcast queue
_event_queue: asyncio.Queue = asyncio.Queue(maxsize=512)

# Connected WebSocket clients
_ws_clients: set[WebSocket] = set()


# ---------------------------------------------------------------------------
# Agent factory helpers
# ---------------------------------------------------------------------------

def _make_llm_client(stack: str, model: str, role: str) -> Any:
    """Return the appropriate LLM client for the selected stack."""
    if stack == "proprietary":
        api_key = os.getenv("GEMINI_API_KEY", "")
        if not api_key:
            logger.warning("GEMINI_API_KEY not set; Gemini client may fail")
        return GeminiClient(api_key=api_key, model=model)
    else:
        # Open-source stack: Groq (free tier) or local Ollama via compatible API
        api_key = os.getenv("GROQ_API_KEY", "")
        os_model = os.getenv("OPENSOURCE_MODEL", "llama-3.3-70b-versatile")
        if not api_key:
            logger.warning("GROQ_API_KEY not set; Groq client may fail")
        return GroqClient(api_key=api_key, model=os_model)


def _build_agents(cfg: dict[str, Any]) -> tuple[list, list]:
    """Instantiate enabled red and blue agents from the current config."""
    stack = cfg["stack"]
    agent_cfg = {
        "temperature": cfg["temperature"],
        "max_tokens": cfg["max_tokens"],
        "verbose": cfg["verbose"],
    }

    red_llm = _make_llm_client(stack, cfg["red_model"], "red")
    blue_llm = _make_llm_client(stack, cfg["blue_model"], "blue")

    red_map = {
        "recon":   lambda: ReconAgent("RedRecon",     red_llm,  agent_cfg),
        "scanner": lambda: ScannerAgent("RedScanner",  red_llm,  agent_cfg),
        "exploit": lambda: ExploitAgent("RedExploit",  red_llm,  agent_cfg),
        "pivot":   lambda: PivotAgent("RedPivot",     red_llm,  agent_cfg),
        "exfil":   lambda: ExfilAgent("RedExfil",     red_llm,  agent_cfg),
    }
    blue_map = {
        "monitor":      lambda: MonitorAgent("BlueMonitor",      llm_client=blue_llm, config=agent_cfg),
        "analyzer":     lambda: AnalyzerAgent("BlueAnalyzer",    llm_client=blue_llm, config=agent_cfg),
        "firewall":     lambda: FirewallAgent("BlueFirewall",    llm_client=blue_llm, config=agent_cfg),
        "responder":    lambda: ResponderAgent("BlueResponder",  llm_client=blue_llm, config=agent_cfg),
        "threat_intel": lambda: ThreatIntelAgent("BlueThreatIntel", llm_client=blue_llm, config=agent_cfg),
    }

    red_agents  = [red_map[k]()  for k in cfg["red_agents_enabled"]  if k in red_map]
    blue_agents = [blue_map[k]() for k in cfg["blue_agents_enabled"] if k in blue_map]

    logger.info(
        "Built %d red agents and %d blue agents (stack=%s)",
        len(red_agents), len(blue_agents), stack,
    )
    return red_agents, blue_agents


# ---------------------------------------------------------------------------
# Simulation loop (runs as a background asyncio task)
# ---------------------------------------------------------------------------

_BLUE_FALLBACKS: dict[str, list[dict]] = {
    "BlueMonitor": [
        {
            "action_name": "Network Traffic Analysis",
            "technique": "Network Traffic Analysis",
            "technique_id": "DE.CM-1",
            "target": "network",
            "result": "partial",
            "reasoning": (
                "Zeek/Suricata IDS captured anomalous SYN packet burst from 10.0.0.5 "
                "toward internal subnet. Baseline deviation: +340% on port 445. "
                "PCAP flagged for deeper analysis – possible SMB lateral movement in progress."
            ),
            "next_intent": "Escalate to AnalyzerAgent for correlation with prior Red Team actions.",
            "confidence": 0.62,
        },
        {
            "action_name": "Log Collection",
            "technique": "Log Monitoring",
            "technique_id": "DE.CM-3",
            "target": "siem",
            "result": "success",
            "reasoning": (
                "Centralised log ingestion (Elastic SIEM): 14,200 events in last 60s. "
                "3 high-severity Sigma rules matched: RDP brute-force, LSASS dump attempt, "
                "and unusual outbound HTTPS to unknown IP. Forwarded IOCs to threat intel feed."
            ),
            "next_intent": "Correlate LSASS dump alert with running processes on affected host.",
            "confidence": 0.71,
        },
        {
            "action_name": "Endpoint Telemetry Review",
            "technique": "Host-based Monitoring",
            "technique_id": "DE.CM-7",
            "target": "endpoints",
            "result": "success",
            "reasoning": (
                "EDR telemetry (CrowdStrike Falcon) flagged suspicious PowerShell: "
                "Invoke-WebRequest to 1.2.3.4:443 with -UseBasicParsing -OutFile C:\\Windows\\Temp\\s.exe. "
                "Process tree: winlogon.exe → cmd.exe → powershell.exe (anomalous parent). "
                "Hash unknown – submitted to VirusTotal sandbox."
            ),
            "next_intent": "Isolate affected endpoint pending forensic review.",
            "confidence": 0.80,
        },
    ],
    "BlueAnalyzer": [
        {
            "action_name": "Alert Correlation",
            "technique": "Threat Analysis",
            "technique_id": "RS.AN-1",
            "target": "siem",
            "result": "success",
            "reasoning": (
                "Correlated 7 low-severity alerts into 1 high-confidence incident: "
                "Recon (T1046) → Exploit (T1190) → Persistence (T1053) chain confirmed. "
                "Kill-chain stage: post-exploitation. Attack group signature matches APT-29 TTP cluster. "
                "Confidence 87% based on MITRE ATT&CK navigator overlay."
            ),
            "next_intent": "Recommend FirewallAgent block C2 IP range and ResponderAgent isolate web-server.",
            "confidence": 0.87,
        },
        {
            "action_name": "Malware Triage",
            "technique": "Malware Analysis",
            "technique_id": "RS.AN-3",
            "target": "web-server",
            "result": "partial",
            "reasoning": (
                "Sandbox detonation of suspicious binary (SHA256: a1b2...): "
                "connects to 185.220.x.x:443 via TLS 1.3 with JA3 fingerprint matching Cobalt Strike. "
                "Beacon interval: 60s ± 30s jitter. DNS resolution for c2.exfiltrate.xyz flagged. "
                "Partial detonation – sample unpacks second-stage loader."
            ),
            "next_intent": "Block C2 domain at DNS and firewall layer; extract additional IOCs from pcap.",
            "confidence": 0.74,
        },
        {
            "action_name": "Timeline Reconstruction",
            "technique": "Forensic Analysis",
            "technique_id": "RS.AN-2",
            "target": "domain-controller",
            "result": "success",
            "reasoning": (
                "Windows Event Log forensics: attacker first appeared at T-00:18 via web shell on IIS. "
                "Lateral movement to DC at T-00:11 via wmiexec (Event ID 4624 Type 3 + 4688). "
                "DCSync attempted at T-00:04 (Event ID 4662 – DS-Replication-Get-Changes-All). "
                "Total dwell time before detection: 18 minutes."
            ),
            "next_intent": "Feed timeline to incident response for full remediation scope.",
            "confidence": 0.91,
        },
    ],
    "BlueFirewall": [
        {
            "action_name": "Dynamic ACL Block",
            "technique": "Network Segmentation",
            "technique_id": "PR.AC-5",
            "target": "perimeter-firewall",
            "result": "success",
            "reasoning": (
                "Applied deny ACE on perimeter firewall: block outbound HTTPS to 185.220.0.0/22 "
                "(known Tor exit / C2 range per Emerging Threats). "
                "Blocked port 4444/TCP egress (common reverse shell). "
                "Added rate-limit on port 445 inter-VLAN: max 10 new connections/sec."
            ),
            "next_intent": "Monitor for C2 beacon rerouting to DNS/ICMP channels.",
            "confidence": 0.83,
        },
        {
            "action_name": "Micro-segmentation Rule",
            "technique": "Network Isolation",
            "technique_id": "PR.AC-5",
            "target": "internal-workstation",
            "result": "success",
            "reasoning": (
                "Pushed NSX micro-segmentation policy: internal-workstation can no longer "
                "initiate SMB (445) or WinRM (5985) to domain-controller. "
                "East-west firewall rule applied in 0.3s via API. "
                "Existing SMB sessions terminated. Potential pivot path disrupted."
            ),
            "next_intent": "Verify no legitimate service depends on this SMB path before permanent rule.",
            "confidence": 0.78,
        },
        {
            "action_name": "IPS Signature Activation",
            "technique": "Intrusion Prevention",
            "technique_id": "DE.CM-1",
            "target": "ids-cluster",
            "result": "success",
            "reasoning": (
                "Activated 12 Snort/Suricata signatures for active campaign IOCs: "
                "ET EXPLOIT Apache CVE-2021-41773, ET MALWARE CobaltStrike Beacon, "
                "ET POLICY Mimikatz User-Agent. "
                "Inline block mode enabled – next matching packet dropped + alert raised."
            ),
            "next_intent": "Tune FP rate on ET POLICY rules before full production rollout.",
            "confidence": 0.76,
        },
    ],
    "BlueResponder": [
        {
            "action_name": "Host Isolation",
            "technique": "Incident Containment",
            "technique_id": "RS.MI-1",
            "target": "web-server",
            "result": "success",
            "reasoning": (
                "Isolated web-server via EDR network containment (CrowdStrike RTR): "
                "host retains C2 channel to EDR cloud but all other network traffic blocked. "
                "Active reverse shell session terminated. Web application unavailable. "
                "Forensic memory dump queued (2.1 GB) for offline analysis."
            ),
            "next_intent": "Restore clean OS image from verified backup; re-enable post patch validation.",
            "confidence": 0.88,
        },
        {
            "action_name": "Credential Reset",
            "technique": "Identity Recovery",
            "technique_id": "RS.MI-3",
            "target": "domain-controller",
            "result": "partial",
            "reasoning": (
                "Force-reset 847 AD accounts flagged in DCSync dump: "
                "kpasswd broadcasts sent. 612/847 resets confirmed in 90s. "
                "235 accounts pending – some mailbox-linked requiring user notification. "
                "KRBTGT account reset (2x, 10h apart) to invalidate golden tickets."
            ),
            "next_intent": "Complete remaining 235 resets; audit service accounts for hardcoded passwords.",
            "confidence": 0.72,
        },
        {
            "action_name": "Persistence Eradication",
            "technique": "Malware Removal",
            "technique_id": "RS.MI-2",
            "target": "internal-workstation",
            "result": "success",
            "reasoning": (
                "Found and removed: cron @reboot /tmp/.update (red team persistence), "
                "registry Run key HKLM\\...\\svchost_update (beacon), "
                "SSH backdoor /root/.ssh/authorized_keys (2nd pubkey removed). "
                "Ran rkhunter + chkrootkit – no additional implants found. "
                "System clock drift detected: attacker used timestomp (-48h shift corrected)."
            ),
            "next_intent": "Validate clean state via file integrity monitoring baseline comparison.",
            "confidence": 0.84,
        },
    ],
    "BlueThreatIntel": [
        {
            "action_name": "IOC Enrichment",
            "technique": "Threat Intelligence",
            "technique_id": "ID.RA-2",
            "target": "threat-intel-platform",
            "result": "success",
            "reasoning": (
                "Enriched 8 IOCs via VirusTotal + AlienVault OTX + MISP: "
                "IP 185.220.x.x → 67/84 AV engines malicious, Tor exit node. "
                "Domain c2.exfiltrate.xyz → registered 3 days ago, DGA pattern match. "
                "SHA256 hash → CobaltStrike Beacon v4.4, associated with APT-41 cluster."
            ),
            "next_intent": "Push enriched IOCs to SIEM and firewall block lists automatically.",
            "confidence": 0.91,
        },
        {
            "action_name": "TTP Mapping",
            "technique": "ATT&CK Mapping",
            "technique_id": "ID.RA-3",
            "target": "mitre-navigator",
            "result": "success",
            "reasoning": (
                "Mapped observed TTPs to MITRE ATT&CK Enterprise v14: "
                "T1190 (exploit), T1059.001 (PowerShell), T1021.002 (SMB), "
                "T1003.001 (LSASS dump), T1041 (C2 exfil). "
                "Pattern matches APT-29 Cozy Bear playbook with 73% confidence. "
                "Recommended detection coverage gaps: T1070.004 (file deletion), T1562.001 (AV disable)."
            ),
            "next_intent": "Brief CISO on attribution assessment and recommended detection improvements.",
            "confidence": 0.73,
        },
        {
            "action_name": "Hunt Query Deployment",
            "technique": "Threat Hunting",
            "technique_id": "DE.CM-8",
            "target": "siem",
            "result": "partial",
            "reasoning": (
                "Deployed 5 proactive hunt queries to Elastic SIEM (EQL): "
                "1. Unusual LSASS access by non-system process. "
                "2. PowerShell download-cradle pattern. "
                "3. WMI lateral movement (wmic /node: process call create). "
                "4. DCSync replication rights abuse (Event ID 4662). "
                "5. Outbound DNS to domains < 7 days old. "
                "Query 4 returned 1 hit – confirmed DCSync event at T-00:04."
            ),
            "next_intent": "Tune query 2 – 12 false positives from legitimate WSUS powershell.",
            "confidence": 0.79,
        },
    ],
}


def _blue_fallback_action(agent_name: str, turn: int, history: list[dict]) -> dict:
    """Generate a contextual blue team fallback action based on agent role and history."""
    import hashlib

    # Find the most recent red team action for context
    last_red = next(
        (h for h in reversed(history) if h.get("agent_team") == "red"),
        {},
    )
    last_red_target = last_red.get("target", "network")
    last_red_technique = last_red.get("technique_id", "T1046")

    fallback_pool = _BLUE_FALLBACKS.get(agent_name, _BLUE_FALLBACKS["BlueMonitor"])
    idx = int(hashlib.md5(f"{agent_name}{turn}".encode()).hexdigest(), 16) % len(fallback_pool)
    template = dict(fallback_pool[idx])

    # Contextualise target with last red team action when relevant
    if template["target"] in ("network", "endpoints") and last_red_target != "network":
        template = dict(template)
        template["target"] = last_red_target
        template["reasoning"] = (
            f"[Responding to {last_red_technique} on {last_red_target}] " + template["reasoning"]
        )

    return {
        "turn": turn,
        "agent_name": agent_name,
        "agent_team": "blue",
        **template,
    }




async def _run_simulation() -> None:
    """
    Drive the red/blue agent loop until the simulation ends or is stopped.

    Each turn:
      1. All red agents act in sequence.
      2. All blue agents act in sequence.
      3. NetworkState advances one turn.
      4. Events are broadcast via SSE / WebSocket.
    """
    global _sim_state

    network: NetworkState = _sim_state["network"]
    red_agents = _sim_state["red_agents"]
    blue_agents = _sim_state["blue_agents"]
    cfg = _sim_state["config"]
    max_turns: int = cfg["max_turns"]
    delay: float = cfg["turn_delay"]

    logger.info("Simulation started (max_turns=%d, delay=%.1fs)", max_turns, delay)
    await _broadcast({"event": "simulation_started", "config": cfg})

    while _sim_state["running"] and network.game_status == "running":
        turn = network.turn_counter

        if turn >= max_turns:
            logger.info("Max turns reached (%d)", max_turns)
            break

        # --- Red team turn ---
        for agent in red_agents:
            if not _sim_state["running"]:
                break
            try:
                state_dict = network.get_state_summary()
                action = await agent.act(state_dict, _sim_state["history"], turn)
                action["turn"] = turn
                action.setdefault("agent_name", agent.name)
                action.setdefault("agent_team", agent.team)
                _sim_state["history"].append(action)
                await _broadcast({"event": "agent_action", "data": action})
                logger.debug("[RED] %s -> %s", agent.name, action.get("action_name"))
            except Exception as exc:
                logger.warning("[RED] %s failed: %s", agent.name, exc)

        # --- Blue team turn ---
        for agent in blue_agents:
            if not _sim_state["running"]:
                break
            try:
                state_dict = network.get_state_summary()
                action = await agent.act(state_dict, _sim_state["history"], turn)
                action["turn"] = turn
                action.setdefault("agent_name", agent.name)
                action.setdefault("agent_team", agent.team)
                _sim_state["history"].append(action)
                await _broadcast({"event": "agent_action", "data": action})
                logger.debug("[BLUE] %s -> %s", agent.name, action.get("action_name"))
            except Exception as exc:
                logger.warning("[BLUE] %s LLM failed – using fallback: %s", agent.name, exc)
                fallback = _blue_fallback_action(agent.name, turn, _sim_state["history"])
                _sim_state["history"].append(fallback)
                await _broadcast({"event": "agent_action", "data": fallback})

        # --- Advance simulation state ---
        network.advance_turn()
        _sim_state["turn"] = network.turn_counter

        # Broadcast full network state snapshot
        await _broadcast({
            "event": "network_state",
            "data": network.get_full_state(),
        })

        if network.game_status != "running":
            break

        await asyncio.sleep(delay)

    _sim_state["running"] = False
    final_status = network.game_status
    logger.info("Simulation ended: %s", final_status)
    await _broadcast({
        "event": "simulation_ended",
        "status": final_status,
        "turns_played": network.turn_counter,
        "history_length": len(_sim_state["history"]),
    })


# ---------------------------------------------------------------------------
# Event broadcasting (SSE + WebSocket fan-out)
# ---------------------------------------------------------------------------

async def _broadcast(payload: dict) -> None:
    """Put an event into the SSE queue and push to all WebSocket clients."""
    try:
        _event_queue.put_nowait(payload)
    except asyncio.QueueFull:
        logger.warning("Event queue full – dropping event: %s", payload.get("event"))

    dead: set[WebSocket] = set()
    for ws in list(_ws_clients):
        try:
            await ws.send_text(json.dumps(payload))
        except Exception:
            dead.add(ws)
    _ws_clients.difference_update(dead)


async def _sse_generator(request: Request) -> AsyncGenerator[str, None]:
    """Async generator that yields SSE-formatted messages from the event queue."""
    # Send the current network state immediately on connect
    if _sim_state["network"] is not None:
        snapshot = _sim_state["network"].get_full_state()
        yield f"data: {json.dumps({'event': 'network_state', 'data': snapshot})}\n\n"

    while True:
        if await request.is_disconnected():
            logger.debug("SSE client disconnected")
            break
        try:
            payload = await asyncio.wait_for(_event_queue.get(), timeout=15.0)
            yield f"data: {json.dumps(payload)}\n\n"
        except asyncio.TimeoutError:
            # Send a keep-alive comment to prevent proxy timeouts
            yield ": keepalive\n\n"


# ---------------------------------------------------------------------------
# Lifespan context manager
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Cyber Agents Demo backend starting up")
    _sim_state["network"] = NetworkState()
    _sim_state["red_agents"], _sim_state["blue_agents"] = _build_agents(_sim_state["config"])
    logger.info("Default agents loaded (stack=%s)", _sim_state["config"]["stack"])

    yield

    # Shutdown
    logger.info("Cyber Agents Demo backend shutting down")
    _sim_state["running"] = False


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Cyber Agents Demo",
    description="Red Team vs Blue Team cybersecurity agent simulation API",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS
_allowed_origins_raw = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173")
_allowed_origins = [o.strip() for o in _allowed_origins_raw.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health", tags=["meta"])
async def health_check():
    return {"status": "ok", "version": "1.0.0"}


# ---------------------------------------------------------------------------
# Simulation control endpoints
# ---------------------------------------------------------------------------

@app.post("/simulation/start", tags=["simulation"])
async def start_simulation():
    """Start the red/blue agent simulation loop."""
    if _sim_state["running"]:
        return {"status": "already_running", "turn": _sim_state["turn"]}

    _sim_state["running"] = True
    _sim_state["network"].game_status = "running"
    asyncio.create_task(_run_simulation())
    logger.info("Simulation start requested via API")
    return {"status": "started", "turn": _sim_state["turn"]}


@app.post("/simulation/stop", tags=["simulation"])
async def stop_simulation():
    """Stop the simulation loop gracefully."""
    _sim_state["running"] = False
    logger.info("Simulation stop requested via API")
    return {"status": "stopped", "turn": _sim_state["turn"]}


@app.post("/simulation/reset", tags=["simulation"])
async def reset_simulation():
    """Reset the simulation to its initial state."""
    _sim_state["running"] = False
    await asyncio.sleep(0.1)  # Allow any running task to notice

    _sim_state["network"] = NetworkState()
    _sim_state["history"] = []
    _sim_state["turn"] = 0
    _sim_state["red_agents"], _sim_state["blue_agents"] = _build_agents(_sim_state["config"])

    await _broadcast({"event": "simulation_reset"})
    logger.info("Simulation reset via API")
    return {"status": "reset"}


@app.get("/simulation/state", tags=["simulation"])
async def get_simulation_state():
    """Return the current full simulation state."""
    network: NetworkState = _sim_state["network"]
    if network is None:
        return {"error": "not initialised"}
    return {
        "running": _sim_state["running"],
        "turn": _sim_state["turn"],
        "config": _sim_state["config"],
        "network": network.get_full_state(),
        "history_length": len(_sim_state["history"]),
    }


@app.get("/simulation/history", tags=["simulation"])
async def get_simulation_history(limit: int = 50):
    """Return the last `limit` agent actions from the history."""
    history = _sim_state["history"]
    return {"history": history[-limit:], "total": len(history)}


# ---------------------------------------------------------------------------
# Configuration endpoint
# ---------------------------------------------------------------------------

@app.get("/config", tags=["config"])
async def get_config():
    return _sim_state["config"]


@app.post("/config", tags=["config"])
async def update_config(body: dict):
    """
    Update simulation configuration parameters.

    Accepted keys: stack, red_model, blue_model, temperature, max_tokens,
    turn_delay, max_turns, red_agents_enabled, blue_agents_enabled, verbose.

    Changes take effect on the NEXT simulation start (or reset).
    """
    allowed_keys = {
        "stack", "red_model", "blue_model", "temperature", "max_tokens",
        "turn_delay", "max_turns", "red_agents_enabled", "blue_agents_enabled",
        "verbose",
    }
    updated: dict[str, Any] = {}
    for key, value in body.items():
        if key in allowed_keys:
            _sim_state["config"][key] = value
            updated[key] = value
        else:
            logger.warning("Config update: unknown key ignored: %s", key)

    if updated:
        logger.info("Config updated: %s", updated)
        # Rebuild agents if stack or model changed and simulation is not running
        if not _sim_state["running"] and any(
            k in updated for k in ("stack", "red_model", "blue_model",
                                   "red_agents_enabled", "blue_agents_enabled")
        ):
            _sim_state["red_agents"], _sim_state["blue_agents"] = _build_agents(_sim_state["config"])
            logger.info("Agents rebuilt after config update")

    return {"status": "updated", "config": _sim_state["config"]}


# ---------------------------------------------------------------------------
# Agent information endpoints
# ---------------------------------------------------------------------------

@app.get("/agents", tags=["agents"])
async def list_agents():
    """List all currently instantiated agents with their metadata."""
    def _agent_info(agent) -> dict:
        return {
            "name": agent.name,
            "team": agent.team,
            "type": agent.__class__.__name__,
            "description": getattr(agent, "description", ""),
            "mitre_techniques": getattr(agent, "mitre_techniques", []),
        }

    return {
        "red_team":  [_agent_info(a) for a in _sim_state["red_agents"]],
        "blue_team": [_agent_info(a) for a in _sim_state["blue_agents"]],
        "stack": _sim_state["config"]["stack"],
    }


# ---------------------------------------------------------------------------
# Network state endpoints
# ---------------------------------------------------------------------------

@app.get("/network", tags=["network"])
async def get_network_state():
    """Return the current network topology and host states."""
    network: NetworkState = _sim_state["network"]
    if network is None:
        return {"error": "not initialised"}
    return network.get_full_state()


@app.get("/network/hosts/{hostname}", tags=["network"])
async def get_host(hostname: str):
    """Return details for a specific host."""
    network: NetworkState = _sim_state["network"]
    if network is None:
        return {"error": "not initialised"}
    host = network.get_host(hostname)
    if host is None:
        return {"error": f"host '{hostname}' not found"}
    return host.to_dict()


# ---------------------------------------------------------------------------
# Server-Sent Events endpoint (real-time stream)
# ---------------------------------------------------------------------------

@app.get("/events", tags=["realtime"])
async def event_stream(request: Request):
    """
    SSE stream of simulation events.

    Events include:
      simulation_started, simulation_ended, simulation_reset,
      agent_action, agent_error, network_state
    """
    return StreamingResponse(
        _sse_generator(request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for bidirectional control.

    Clients receive the same events as the SSE stream.
    Clients may send JSON commands:
      {"cmd": "start"}
      {"cmd": "stop"}
      {"cmd": "reset"}
      {"cmd": "config", "data": {...}}
    """
    await websocket.accept()
    _ws_clients.add(websocket)
    logger.info("WebSocket client connected (total=%d)", len(_ws_clients))

    # Send initial state snapshot
    if _sim_state["network"] is not None:
        await websocket.send_text(json.dumps({
            "event": "network_state",
            "data": _sim_state["network"].get_full_state(),
        }))

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send_text(json.dumps({"error": "invalid JSON"}))
                continue

            cmd = msg.get("cmd", "")
            if cmd == "start":
                if not _sim_state["running"]:
                    _sim_state["running"] = True
                    asyncio.create_task(_run_simulation())
                await websocket.send_text(json.dumps({"status": "started"}))

            elif cmd == "stop":
                _sim_state["running"] = False
                await websocket.send_text(json.dumps({"status": "stopped"}))

            elif cmd == "reset":
                _sim_state["running"] = False
                await asyncio.sleep(0.1)
                _sim_state["network"] = NetworkState()
                _sim_state["history"] = []
                _sim_state["turn"] = 0
                _sim_state["red_agents"], _sim_state["blue_agents"] = _build_agents(_sim_state["config"])
                await _broadcast({"event": "simulation_reset"})
                await websocket.send_text(json.dumps({"status": "reset"}))

            elif cmd == "config":
                data = msg.get("data", {})
                allowed = {
                    "stack", "red_model", "blue_model", "temperature", "max_tokens",
                    "turn_delay", "max_turns", "red_agents_enabled",
                    "blue_agents_enabled", "verbose",
                }
                for k, v in data.items():
                    if k in allowed:
                        _sim_state["config"][k] = v
                await websocket.send_text(json.dumps({
                    "status": "config_updated",
                    "config": _sim_state["config"],
                }))

            else:
                await websocket.send_text(json.dumps({
                    "error": f"unknown command: {cmd!r}",
                    "valid_commands": ["start", "stop", "reset", "config"],
                }))

    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected")
    finally:
        _ws_clients.discard(websocket)


# ---------------------------------------------------------------------------
# Entry point (for direct execution: python main.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("DEV_MODE", "false").lower() == "true",
        log_level=LOG_LEVEL.lower(),
    )
