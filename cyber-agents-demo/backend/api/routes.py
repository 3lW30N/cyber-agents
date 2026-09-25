"""
FastAPI router for the cyber-agents-demo backend.

Endpoints
---------
POST   /api/scenarios/start
GET    /api/scenarios/stream/{session_id}
POST   /api/scenarios/pause/{session_id}
PUT    /api/scenarios/resume/{session_id}
POST   /api/scenarios/reset/{session_id}
GET    /api/config/stacks
GET    /api/scenarios
GET    /api/scenarios/{session_id}/state
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from typing import Any, AsyncGenerator, Dict, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Internal imports
# ---------------------------------------------------------------------------
from simulation.network_state import NetworkState
from api.sse import EventQueue, event_generator, format_sse

logger = logging.getLogger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# Available stacks metadata
# ---------------------------------------------------------------------------

STACKS = [
    {
        "name": "gemini",
        "model": "gemini-2.5-flash",
        "provider": "Google",
        "is_free": True,
        "description": "Proprietary stack — Google Gemini 2.5 Flash via Gemini API",
    },
    {
        "name": "groq",
        "model": "llama-3.3-70b-versatile",
        "provider": "Groq",
        "is_free": True,
        "description": "Open-source stack — Llama 3.1 8B via Groq ultra-fast inference",
    },
]

# ---------------------------------------------------------------------------
# Available scenarios
# ---------------------------------------------------------------------------

SCENARIOS: list[dict] = [
    {
        "id": "network_intrusion",
        "name": "Network Intrusion",
        "description": (
            "A red team attacker attempts to move through a corporate network "
            "(web server → workstation → domain controller) while a blue team "
            "defends in real-time using monitoring, threat-intel, analysis, "
            "firewall, and incident-response agents."
        ),
        "max_turns": 20,
        "hosts": ["web-server", "db-server", "mail-server", "internal-workstation", "domain-controller"],
        "red_agents": ["ReconAgent", "ScannerAgent", "ExploitAgent", "PivotAgent", "ExfilAgent"],
        "blue_agents": ["MonitorAgent", "ThreatIntelAgent", "AnalyzerAgent", "FirewallAgent", "ResponderAgent"],
    },
]

# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class ScenarioConfig(BaseModel):
    aggression: int = Field(default=5, ge=1, le=10, description="Red team aggression level 1-10")
    detection_sensitivity: int = Field(default=5, ge=1, le=10, description="Blue team sensitivity 1-10")
    speed_ms: int = Field(default=1500, ge=100, le=10000, description="Milliseconds between turns")


class StartScenarioRequest(BaseModel):
    stack: str = Field(..., description="'gemini' or 'groq'")
    scenario: str = Field(default="network_intrusion")
    config: ScenarioConfig = Field(default_factory=ScenarioConfig)


# ---------------------------------------------------------------------------
# In-process game engine (lazy import to avoid circular deps at module level)
# ---------------------------------------------------------------------------

def _build_game_engine(
    network_state: NetworkState,
    red_agents: list,
    blue_agents: list,
    config: ScenarioConfig,
    event_queue: EventQueue,
):
    """
    Import and instantiate GameEngine.  The import is deferred so that
    simulation.engine is not loaded until an actual game starts (faster cold
    start for API-only health checks).
    """
    try:
        from simulation.game_engine import GameEngine  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "simulation.game_engine module not found. "
            "Make sure backend/simulation/game_engine.py exists."
        ) from exc

    return GameEngine(
        network_state=network_state,
        red_agents=red_agents,
        blue_agents=blue_agents,
        config={
            "aggression": config.aggression,
            "detection_sensitivity": config.detection_sensitivity,
            "speed_ms": config.speed_ms,
        },
        event_queue=event_queue,
    )


def _build_llm_client(stack: str):
    """Instantiate the LLM client for the requested stack."""
    if stack == "gemini":
        api_key = os.environ.get("GEMINI_API_KEY", "")
        if not api_key:
            raise HTTPException(
                status_code=400,
                detail=(
                    "GEMINI_API_KEY environment variable is not set. "
                    "Add it to your .env file or export it in your shell before "
                    "starting the server."
                ),
            )
        try:
            from llm.gemini_client import GeminiClient  # type: ignore
        except ImportError as exc:
            raise HTTPException(
                status_code=500,
                detail=f"Could not import GeminiClient: {exc}",
            )
        return GeminiClient(api_key=api_key)

    elif stack == "groq":
        api_key = os.environ.get("GROQ_API_KEY", "")
        if not api_key:
            raise HTTPException(
                status_code=400,
                detail=(
                    "GROQ_API_KEY environment variable is not set. "
                    "Add it to your .env file or export it in your shell before "
                    "starting the server."
                ),
            )
        try:
            from llm.groq_client import GroqClient  # type: ignore
        except ImportError as exc:
            raise HTTPException(
                status_code=500,
                detail=f"Could not import GroqClient: {exc}",
            )
        return GroqClient(api_key=api_key)

    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown stack '{stack}'. Valid values: 'gemini', 'groq'.",
        )


def _build_agents(llm_client, config: ScenarioConfig) -> tuple[list, list]:
    """Instantiate all red-team and blue-team agent instances."""
    agent_config: dict[str, Any] = {
        "temperature": 0.7,
        "max_tokens": 512,
        "verbose": False,
        "aggression": config.aggression,
        "detection_sensitivity": config.detection_sensitivity,
    }

    # --- Red team ---
    try:
        from agents.red_team.recon_agent import ReconAgent  # type: ignore
        from agents.red_team.scanner_agent import ScannerAgent  # type: ignore
        from agents.red_team.exploit_agent import ExploitAgent  # type: ignore
        from agents.red_team.pivot_agent import PivotAgent  # type: ignore
        from agents.red_team.exfil_agent import ExfilAgent  # type: ignore
    except ImportError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to import red team agents: {exc}",
        )

    red_agents = [
        ReconAgent(name="ReconAgent", team="red", llm_client=llm_client, config=agent_config),
        ScannerAgent(name="ScannerAgent", team="red", llm_client=llm_client, config=agent_config),
        ExploitAgent(name="ExploitAgent", team="red", llm_client=llm_client, config=agent_config),
        PivotAgent(name="PivotAgent", team="red", llm_client=llm_client, config=agent_config),
        ExfilAgent(name="ExfilAgent", team="red", llm_client=llm_client, config=agent_config),
    ]

    # --- Blue team ---
    try:
        from agents.blue_team.monitor_agent import MonitorAgent  # type: ignore
        from agents.blue_team.threat_intel_agent import ThreatIntelAgent  # type: ignore
        from agents.blue_team.analyzer_agent import AnalyzerAgent  # type: ignore
        from agents.blue_team.firewall_agent import FirewallAgent  # type: ignore
        from agents.blue_team.responder_agent import ResponderAgent  # type: ignore
    except ImportError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to import blue team agents: {exc}",
        )

    blue_agents = [
        MonitorAgent(name="MonitorAgent", team="blue", llm_client=llm_client, config=agent_config),
        ThreatIntelAgent(name="ThreatIntelAgent", team="blue", llm_client=llm_client, config=agent_config),
        AnalyzerAgent(name="AnalyzerAgent", team="blue", llm_client=llm_client, config=agent_config),
        FirewallAgent(name="FirewallAgent", team="blue", llm_client=llm_client, config=agent_config),
        ResponderAgent(name="ResponderAgent", team="blue", llm_client=llm_client, config=agent_config),
    ]

    return red_agents, blue_agents


# ---------------------------------------------------------------------------
# Session store helpers
# ---------------------------------------------------------------------------

def _get_sessions(request: Request) -> dict:
    if not hasattr(request.app.state, "sessions"):
        request.app.state.sessions = {}
    return request.app.state.sessions


def _require_session(request: Request, session_id: str) -> dict:
    sessions = _get_sessions(request)
    session = sessions.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")
    return session


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

# -- Config ----------------------------------------------------------------

@router.get("/api/config/stacks")
async def get_stacks():
    """Return the list of available LLM stacks."""
    return STACKS


# -- Scenario catalogue ----------------------------------------------------

@router.get("/api/scenarios")
async def list_scenarios():
    """Return the list of available scenarios."""
    return SCENARIOS


# -- Start a scenario session ----------------------------------------------

@router.post("/api/scenarios/start")
async def start_scenario(body: StartScenarioRequest, request: Request):
    """
    Initialise a new simulation session.

    - Validates the requested stack and scenario.
    - Builds LLM client, agents, NetworkState, and GameEngine.
    - Stores the session in ``app.state.sessions``.
    - Returns the session ID, scenario metadata, and the initial network state.
    """
    # Validate scenario
    scenario_meta = next((s for s in SCENARIOS if s["id"] == body.scenario), None)
    if scenario_meta is None:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scenario '{body.scenario}'. Valid: {[s['id'] for s in SCENARIOS]}",
        )

    # Build LLM client (raises HTTPException on missing key)
    llm_client = _build_llm_client(body.stack)

    # Build agents
    red_agents, blue_agents = _build_agents(llm_client, body.config)

    # Build network state
    network_state = NetworkState()

    # Event queue for streaming
    event_queue = EventQueue()

    # Build game engine
    try:
        game_engine = _build_game_engine(
            network_state=network_state,
            red_agents=red_agents,
            blue_agents=blue_agents,
            config=body.config,
            event_queue=event_queue,
        )
    except RuntimeError as exc:
        # simulation.engine not yet implemented — create a stub that still
        # lets the SSE endpoint work for frontend development purposes.
        logger.warning("GameEngine not available (%s); using stub.", exc)
        game_engine = None

    session_id = str(uuid.uuid4())

    sessions = _get_sessions(request)
    sessions[session_id] = {
        "session_id": session_id,
        "stack": body.stack,
        "scenario": body.scenario,
        "config": body.config.model_dump(),
        "network_state": network_state,
        "game_engine": game_engine,
        "event_queue": event_queue,
        "status": "ready",   # ready | running | paused | finished
        "llm_client": llm_client,
        "_task": None,       # asyncio Task reference for the game loop
    }

    logger.info("Session %s created (stack=%s, scenario=%s)", session_id, body.stack, body.scenario)

    return {
        "session_id": session_id,
        "scenario": scenario_meta,
        "network_state": network_state.get_full_state(),
    }


# -- SSE stream ------------------------------------------------------------

@router.get("/api/scenarios/stream/{session_id}")
async def stream_scenario(session_id: str, request: Request):
    """
    Server-Sent Events endpoint.

    Opens a persistent HTTP connection and streams simulation events as they
    occur.  Each event is a JSON object with at least::

        {
          "type":          "action" | "alert" | "game_over" | "turn_start",
          "team":          "red" | "blue" | null,
          "agent":         "<agent name>",
          "turn":          <int>,
          "action":        { ... AgentAction ... },
          "network_state": { ... NetworkState.get_full_state() ... },
          "scores":        { "red": <int>, "blue": <int> }
        }

    The stream ends with a ``game_over`` event.
    """
    session = _require_session(request, session_id)

    if session["status"] == "running":
        raise HTTPException(status_code=409, detail="Scenario is already streaming.")
    if session["status"] == "finished":
        raise HTTPException(status_code=410, detail="Scenario has already finished.")

    session["status"] = "running"
    event_queue: EventQueue = session["event_queue"]
    game_engine = session["game_engine"]

    async def _run_game():
        """Background coroutine: drives the game engine and pushes events."""
        try:
            if game_engine is not None and hasattr(game_engine, "run"):
                await game_engine.run()
            else:
                # Stub: emit a few fake events so the frontend can be demoed
                # even if simulation/game_engine.py has not been implemented yet.
                await _stub_game_loop(session, event_queue)
        except asyncio.CancelledError:
            logger.info("Game loop for session %s was cancelled.", session_id)
        except Exception as exc:
            logger.exception("Game loop error for session %s: %s", session_id, exc)
            await event_queue.put({
                "_sse_event": "error",
                "type": "error",
                "message": str(exc),
            })
        finally:
            session["status"] = "finished"
            await event_queue.close()

    # Launch the game loop as a background asyncio task so the streaming
    # response can drain the queue concurrently.
    task = asyncio.create_task(_run_game())
    session["_task"] = task

    headers = {
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    }

    return StreamingResponse(
        event_generator(event_queue, timeout=90.0),
        media_type="text/event-stream",
        headers=headers,
    )


# -- Control endpoints ------------------------------------------------------

@router.post("/api/scenarios/pause/{session_id}")
async def pause_scenario(session_id: str, request: Request):
    """Pause a running simulation."""
    session = _require_session(request, session_id)
    if session["status"] != "running":
        raise HTTPException(
            status_code=409,
            detail=f"Cannot pause: session status is '{session['status']}'.",
        )
    game_engine = session.get("game_engine")
    if game_engine is not None and hasattr(game_engine, "pause"):
        game_engine.pause()
    session["status"] = "paused"
    return {"session_id": session_id, "status": "paused"}


@router.put("/api/scenarios/resume/{session_id}")
async def resume_scenario(session_id: str, request: Request):
    """Resume a paused simulation."""
    session = _require_session(request, session_id)
    if session["status"] != "paused":
        raise HTTPException(
            status_code=409,
            detail=f"Cannot resume: session status is '{session['status']}'.",
        )
    game_engine = session.get("game_engine")
    if game_engine is not None and hasattr(game_engine, "resume"):
        game_engine.resume()
    session["status"] = "running"
    return {"session_id": session_id, "status": "running"}


@router.post("/api/scenarios/reset/{session_id}")
async def reset_scenario(session_id: str, request: Request):
    """
    Reset a session back to its initial state.

    - Cancels any running game task.
    - Resets the NetworkState.
    - Creates a fresh EventQueue.
    - Status is set back to 'ready'.
    """
    session = _require_session(request, session_id)

    # Cancel running task if any
    task: Optional[asyncio.Task] = session.get("_task")
    if task and not task.done():
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

    # Reset network state
    network_state: NetworkState = session["network_state"]
    network_state.reset()

    # Fresh event queue
    session["event_queue"] = EventQueue()
    session["status"] = "ready"
    session["_task"] = None

    # Rebuild engine with fresh queue if possible
    game_engine = session.get("game_engine")
    if game_engine is not None and hasattr(game_engine, "reset"):
        game_engine.reset(event_queue=session["event_queue"])

    logger.info("Session %s reset.", session_id)
    return {
        "session_id": session_id,
        "status": "ready",
        "network_state": network_state.get_full_state(),
    }


# -- State snapshot --------------------------------------------------------

@router.get("/api/scenarios/{session_id}/state")
async def get_scenario_state(session_id: str, request: Request):
    """Return a snapshot of the current network state for the given session."""
    session = _require_session(request, session_id)
    network_state: NetworkState = session["network_state"]
    return {
        "session_id": session_id,
        "status": session["status"],
        "network_state": network_state.get_full_state(),
    }


# ---------------------------------------------------------------------------
# Stub game loop (used when simulation.engine is not yet implemented)
# ---------------------------------------------------------------------------

async def _stub_game_loop(session: dict, event_queue: EventQueue) -> None:
    """
    Emit a series of synthetic events to allow frontend development before
    the real GameEngine is in place.
    """
    import random

    network_state: NetworkState = session["network_state"]
    config: dict = session["config"]
    speed_ms: int = config.get("speed_ms", 1500)
    delay: float = speed_ms / 1000.0

    red_agents = ["ReconAgent", "ScannerAgent", "ExploitAgent", "PivotAgent", "ExfilAgent"]
    blue_agents = ["MonitorAgent", "ThreatIntelAgent", "AnalyzerAgent", "FirewallAgent", "ResponderAgent"]

    red_actions = [
        ("Passive Reconnaissance", "T1590", "web-server"),
        ("Port Scan", "T1046", "web-server"),
        ("Exploit Apache CVE-2021-41773", "T1190", "web-server"),
        ("Lateral Movement via SMB", "T1021.002", "internal-workstation"),
        ("Data Exfiltration via DNS", "T1048.003", "domain-controller"),
    ]
    blue_actions = [
        ("Network Traffic Monitoring", "T1040", "web-server"),
        ("IOC Enrichment", "T1595", "web-server"),
        ("Alert Correlation", "T1595.002", "web-server"),
        ("Firewall Rule Deployment", "T1562.001", "internal-workstation"),
        ("Host Isolation", "T1562.001", "domain-controller"),
    ]

    scores = {"red": 0, "blue": 0}

    for turn in range(1, 11):
        if session.get("status") == "paused":
            # Poll until resumed
            while session.get("status") == "paused":
                await asyncio.sleep(0.2)

        network_state.advance_turn()

        # Emit turn_start
        await event_queue.put({
            "_sse_event": "turn_start",
            "type": "turn_start",
            "turn": turn,
            "network_state": network_state.get_full_state(),
            "scores": dict(scores),
            "team": None,
            "agent": None,
            "action": None,
        })
        await asyncio.sleep(delay * 0.2)

        # Red action
        red_agent = red_agents[(turn - 1) % len(red_agents)]
        r_name, r_tid, r_target = red_actions[(turn - 1) % len(red_actions)]
        r_result = random.choice(["success", "partial", "blocked"])
        if r_result == "success":
            scores["red"] += 20
            # Mark compromise on success
            targets = list(network_state.hosts.keys())
            chosen = random.choice(targets)
            network_state.update_compromise(chosen, "foothold")
        elif r_result == "partial":
            scores["red"] += 5

        red_event = {
            "_sse_event": "action",
            "type": "action",
            "team": "red",
            "agent": red_agent,
            "turn": turn,
            "action": {
                "action_name": r_name,
                "technique": r_name,
                "technique_id": r_tid,
                "target": r_target,
                "result": r_result,
                "reasoning": f"[stub] Turn {turn} — {r_name} against {r_target}",
                "next_intent": "Escalate privileges",
                "confidence": round(random.uniform(0.6, 0.95), 2),
                "details": {},
                "agent_name": red_agent,
                "agent_team": "red",
            },
            "network_state": network_state.get_full_state(),
            "scores": dict(scores),
        }
        await event_queue.put(red_event)
        await asyncio.sleep(delay * 0.4)

        # Blue response
        blue_agent = blue_agents[(turn - 1) % len(blue_agents)]
        b_name, b_tid, b_target = blue_actions[(turn - 1) % len(blue_actions)]
        b_result = random.choice(["success", "partial", "blocked"])
        if b_result == "success":
            scores["blue"] += 15

        blue_event = {
            "_sse_event": "action",
            "type": "action",
            "team": "blue",
            "agent": blue_agent,
            "turn": turn,
            "action": {
                "action_name": b_name,
                "technique": b_name,
                "technique_id": b_tid,
                "target": b_target,
                "result": b_result,
                "reasoning": f"[stub] Turn {turn} — {b_name} on {b_target}",
                "next_intent": "Continue monitoring",
                "confidence": round(random.uniform(0.6, 0.95), 2),
                "details": {},
                "agent_name": blue_agent,
                "agent_team": "blue",
            },
            "network_state": network_state.get_full_state(),
            "scores": dict(scores),
        }
        await event_queue.put(blue_event)
        await asyncio.sleep(delay * 0.4)

        if network_state.game_status != "running":
            break

    # Final game-over event
    winner = network_state.game_status  # red_wins / blue_wins / running (draw)
    if winner == "running":
        winner = "draw"

    await event_queue.put({
        "_sse_event": "game_over",
        "type": "game_over",
        "winner": winner,
        "turn": network_state.turn_counter,
        "network_state": network_state.get_full_state(),
        "scores": scores,
        "team": None,
        "agent": None,
        "action": None,
    })
