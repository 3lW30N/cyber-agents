"""
GameEngine: orchestrates Red Team vs Blue Team simulation, turn by turn.

Turn sequence:
  1. Select active Red agent (based on kill-chain progression)
  2. Red agent acts → AgentAction JSON
  3. Apply result to NetworkState
  4. Trigger relevant Blue agents
  5. Blue agents respond → update NetworkState (alerts, blocks, isolations)
  6. Emit list of SSE-ready event dicts
  7. Check win conditions
  8. Sleep for configured speed_ms
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, AsyncGenerator, Optional

from agents.red_team import ReconAgent, ScannerAgent, ExploitAgent, PivotAgent, ExfilAgent
from agents.blue_team import MonitorAgent, ThreatIntelAgent, AnalyzerAgent, FirewallAgent, ResponderAgent
from simulation.network_state import NetworkState

logger = logging.getLogger(__name__)

# Kill-chain phases mapped to agent keys
KILL_CHAIN = ["recon", "scan", "exploit", "pivot", "exfil"]

RED_AGENT_MAP = {
    "recon":   "recon_agent",
    "scan":    "scanner_agent",
    "exploit": "exploit_agent",
    "pivot":   "pivot_agent",
    "exfil":   "exfil_agent",
}

# Which Blue agents respond to each Red phase
BLUE_RESPONDERS: dict[str, list[str]] = {
    "recon":   ["monitor_agent"],
    "scan":    ["monitor_agent", "threat_intel_agent"],
    "exploit": ["monitor_agent", "analyzer_agent", "firewall_agent"],
    "pivot":   ["monitor_agent", "analyzer_agent", "firewall_agent", "responder_agent"],
    "exfil":   ["monitor_agent", "analyzer_agent", "firewall_agent", "responder_agent", "threat_intel_agent"],
}


class GameEngine:
    def __init__(
        self,
        network_state: NetworkState,
        llm_client: Any = None,
        config: dict | None = None,
        red_agents: list | None = None,
        blue_agents: list | None = None,
        event_queue: Any = None,  # optional EventQueue, unused internally (we yield events)
    ):
        self.network_state = network_state
        self.llm_client = llm_client
        self.config = {
            "aggression": int((config or {}).get("aggression", 5)),
            "detection_sensitivity": int((config or {}).get("detection_sensitivity", 5)),
            "speed_ms": int((config or {}).get("speed_ms", 2000)),
            "max_turns": int((config or {}).get("max_turns", 20)),
        }
        self._event_queue = event_queue

        self._running = False
        self._paused = False
        self._turn = 0
        self._consecutive_detections = 0
        self._history: list[dict] = []
        self._phase_index = 0

        agent_cfg_red  = {"aggression": self.config["aggression"]}
        agent_cfg_blue = {"detection_sensitivity": self.config["detection_sensitivity"]}

        # Accept pre-built agent lists (from routes.py) or build from llm_client
        if red_agents is not None:
            self.red_agents = self._index_agents(red_agents, RED_AGENT_MAP)
        else:
            self.red_agents = {
                "recon_agent":   ReconAgent(name="ReconAgent",   llm_client=llm_client, config=agent_cfg_red),
                "scanner_agent": ScannerAgent(name="ScannerAgent", llm_client=llm_client, config=agent_cfg_red),
                "exploit_agent": ExploitAgent(name="ExploitAgent", llm_client=llm_client, config=agent_cfg_red),
                "pivot_agent":   PivotAgent(name="PivotAgent",   llm_client=llm_client, config=agent_cfg_red),
                "exfil_agent":   ExfilAgent(name="ExfilAgent",   llm_client=llm_client, config=agent_cfg_red),
            }

        if blue_agents is not None:
            self.blue_agents = self._index_blue_agents(blue_agents)
        else:
            self.blue_agents = {
                "monitor_agent":      MonitorAgent(name="MonitorAgent",      llm_client=llm_client, config=agent_cfg_blue),
                "threat_intel_agent": ThreatIntelAgent(name="ThreatIntelAgent", llm_client=llm_client, config=agent_cfg_blue),
                "analyzer_agent":     AnalyzerAgent(name="AnalyzerAgent",     llm_client=llm_client, config=agent_cfg_blue),
                "firewall_agent":     FirewallAgent(name="FirewallAgent",     llm_client=llm_client, config=agent_cfg_blue),
                "responder_agent":    ResponderAgent(name="ResponderAgent",    llm_client=llm_client, config=agent_cfg_blue),
            }

    @staticmethod
    def _index_agents(agents: list, phase_map: dict) -> dict:
        """Index pre-built agents by their snake_case key derived from class name."""
        indexed = {}
        for agent in agents:
            key = agent.__class__.__name__.lower().replace("agent", "_agent")
            # fallback: use name attribute
            if hasattr(agent, "name"):
                key = agent.name.lower().replace("agent", "_agent").strip("_") + "_agent"
                key = key.replace("__", "_")
            indexed[key] = agent
        # Ensure all phase keys exist by matching class name fragments
        result = {}
        for phase_key, agent_key in phase_map.items():
            for k, a in indexed.items():
                cname = a.__class__.__name__.lower()
                if phase_key in cname or agent_key.replace("_agent", "") in cname:
                    result[agent_key] = a
                    break
        return result or indexed

    @staticmethod
    def _index_blue_agents(agents: list) -> dict:
        """Index blue team agents by snake_case key."""
        name_map = {
            "monitor": "monitor_agent",
            "analyzer": "analyzer_agent",
            "firewall": "firewall_agent",
            "responder": "responder_agent",
            "threatintel": "threat_intel_agent",
            "threat_intel": "threat_intel_agent",
        }
        indexed = {}
        for agent in agents:
            cname = agent.__class__.__name__.lower().replace("agent", "").strip("_")
            key = name_map.get(cname, cname + "_agent")
            indexed[key] = agent
        return indexed

    # ── Properties ───────────────────────────────────────────────────────────

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def current_turn(self) -> int:
        return self._turn

    # ── Control ───────────────────────────────────────────────────────────────

    def pause(self) -> None:
        self._paused = True

    def resume(self) -> None:
        self._paused = False

    def reset(self) -> None:
        self._running = False
        self._paused = False
        self._turn = 0
        self._consecutive_detections = 0
        self._history.clear()
        self._phase_index = 0
        self.network_state.reset()

    # ── Phase logic ──────────────────────────────────────────────────────────

    def _advance_phase(self) -> None:
        """Move to next kill-chain phase if current conditions are met."""
        state = self.network_state
        compromised = [h for h in state.hosts.values() if h.compromise_status != "none"]

        if self._phase_index == 0 and self._turn >= 1:
            self._phase_index = 1
        elif self._phase_index == 1 and len(compromised) == 0:
            pass  # stay on scan until something is found
        elif self._phase_index == 1 and len(state.red_team_knowledge) > 0:
            self._phase_index = 2
        elif self._phase_index == 2 and len(compromised) >= 1:
            self._phase_index = 3
        elif self._phase_index == 3 and len(compromised) >= 2:
            self._phase_index = 4

    def get_active_red_agent(self) -> tuple[str, str]:
        """Returns (agent_key, phase_name)."""
        self._advance_phase()
        phase = KILL_CHAIN[self._phase_index]
        return RED_AGENT_MAP[phase], phase

    # ── Win condition ────────────────────────────────────────────────────────

    def check_win_condition(self) -> Optional[str]:
        dc = self.network_state.get_host("domain-controller")
        if dc and dc.compromise_status == "owned":
            return "red_wins"

        if self.network_state.game_status in ("red_wins", "blue_wins"):
            return self.network_state.game_status

        all_isolated = all(
            h.is_isolated or h.compromise_status == "none"
            for h in self.network_state.hosts.values()
            if h.hostname != "domain-controller"
        )
        if self._consecutive_detections >= 3 and all_isolated:
            return "blue_wins"

        if self._turn >= self.config["max_turns"]:
            # Draw: blue holds if DC not compromised
            compromised_count = sum(
                1 for h in self.network_state.hosts.values()
                if h.compromise_status == "owned"
            )
            return "blue_wins" if compromised_count == 0 else "red_wins"

        return None

    # ── Single turn ──────────────────────────────────────────────────────────

    async def run_turn(self) -> list[dict]:
        events: list[dict] = []
        self._turn += 1
        ts = time.time()

        agent_key, phase = self.get_active_red_agent()
        red_agent = self.red_agents[agent_key]
        state_dict = self.network_state.get_full_state()

        events.append({
            "type": "turn_start",
            "turn": self._turn,
            "phase": phase,
            "active_red_agent": red_agent.name,
            "timestamp": ts,
            "network_state": state_dict,
            "scores": self._compute_scores(),
        })

        # ── Red agent acts ────────────────────────────────────────────────
        try:
            red_action: dict = await red_agent.act(
                network_state_dict=state_dict,
                history=self._history[-10:],
                turn=self._turn,
            )
        except Exception as exc:
            logger.warning("Red agent %s failed: %s", red_agent.name, exc)
            red_action = {
                "action_name": "failed",
                "technique": "unknown",
                "technique_id": "T0000",
                "target": "unknown",
                "result": "blocked",
                "reasoning": f"Agent error: {exc}",
                "next_intent": "retry",
                "confidence": 0.0,
                "details": {},
            }

        # Apply red action to state
        self._apply_red_action(red_action)

        red_event = {
            "type": "agent_action",
            "team": "red",
            "agent": red_agent.name,
            "turn": self._turn,
            "action": red_action,
            "network_state": self.network_state.get_full_state(),
            "scores": self._compute_scores(),
            "timestamp": time.time(),
        }
        events.append(red_event)
        self._history.append({"agent_team": "red", "agent": red_agent.name, **red_action})

        # ── Blue agents respond ───────────────────────────────────────────
        responder_keys = BLUE_RESPONDERS.get(phase, ["monitor_agent"])
        updated_state = self.network_state.get_full_state()
        detected_this_turn = False

        for blue_key in responder_keys:
            blue_agent = self.blue_agents.get(blue_key)
            if not blue_agent:
                continue
            try:
                blue_action: dict = await blue_agent.act(
                    network_state_dict=updated_state,
                    history=self._history[-10:],
                    turn=self._turn,
                )
            except Exception as exc:
                logger.warning("Blue agent %s failed: %s", blue_agent.name, exc)
                continue

            # Apply blue action
            detection = self._apply_blue_action(blue_action)
            if detection:
                detected_this_turn = True

            updated_state = self.network_state.get_full_state()
            blue_event = {
                "type": "agent_action",
                "team": "blue",
                "agent": blue_agent.name,
                "turn": self._turn,
                "action": blue_action,
                "network_state": updated_state,
                "scores": self._compute_scores(),
                "timestamp": time.time(),
            }
            events.append(blue_event)
            self._history.append({"agent_team": "blue", "agent": blue_agent.name, **blue_action})

            # Emit alert if severity is high
            result = blue_action.get("result", "")
            if result in ("detected", "blocked") or blue_action.get("alert_triggered"):
                sev = blue_action.get("alert_severity", "medium")
                if sev in ("high", "critical"):
                    events.append({
                        "type": "alert",
                        "severity": sev,
                        "message": blue_action.get("reasoning", "Threat detected")[:120],
                        "source_agent": blue_agent.name,
                        "affected_host": red_action.get("target", "unknown"),
                        "timestamp": time.time(),
                    })

        if detected_this_turn:
            self._consecutive_detections += 1
        else:
            self._consecutive_detections = 0

        # ── State update ──────────────────────────────────────────────────
        events.append({
            "type": "state_update",
            "turn": self._turn,
            "network_state": self.network_state.get_full_state(),
            "scores": self._compute_scores(),
            "timestamp": time.time(),
        })

        # ── Win check ─────────────────────────────────────────────────────
        winner = self.check_win_condition()
        if winner:
            self._running = False
            events.append({
                "type": "game_over",
                "winner": winner.replace("_wins", ""),
                "reason": self._win_reason(winner),
                "final_scores": self._compute_scores(),
                "turn": self._turn,
                "timestamp": time.time(),
            })

        return events

    # ── Full game loop ────────────────────────────────────────────────────────

    async def run_game(self) -> AsyncGenerator[dict, None]:
        self._running = True
        self._paused = False

        yield {
            "type": "simulation_status",
            "status": "started",
            "stack": getattr(self.llm_client, "provider", "unknown"),
            "config": self.config,
            "timestamp": time.time(),
        }

        while self._running:
            # Respect pause
            while self._paused and self._running:
                await asyncio.sleep(0.2)

            if not self._running:
                break

            try:
                turn_events = await self.run_turn()
                for event in turn_events:
                    yield event
            except Exception as exc:
                logger.error("Turn %d failed: %s", self._turn, exc)
                yield {
                    "type": "error",
                    "message": str(exc),
                    "turn": self._turn,
                    "timestamp": time.time(),
                }
                break

            # Yield heartbeat then sleep
            yield {"type": "heartbeat", "timestamp": time.time()}
            await asyncio.sleep(self.config["speed_ms"] / 1000)

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _apply_red_action(self, action: dict) -> None:
        target = action.get("target", "")
        result = action.get("result", "blocked")
        technique_id = action.get("technique_id", "")

        if result in ("success", "partial") and target:
            host = self.network_state.get_host(target)
            if host:
                # Progress compromise based on phase
                if self._phase_index >= 2 and host.compromise_status == "none":
                    self.network_state.update_compromise(target, "foothold")
                elif self._phase_index >= 3 and host.compromise_status == "foothold":
                    self.network_state.update_compromise(target, "owned")

                # Record knowledge
                if target not in self.network_state.red_team_knowledge:
                    self.network_state.red_team_knowledge[target] = []
                self.network_state.red_team_knowledge[target].append(
                    action.get("technique", "unknown")
                )

    def _apply_blue_action(self, action: dict) -> bool:
        """Apply blue team action to network state. Returns True if detection occurred."""
        detected = False
        result = action.get("result", "")
        details = action.get("details", {})

        # Alert
        if action.get("alert_triggered") or result in ("detected", "blocked"):
            detected = True
            self.network_state.add_alert({
                "severity": action.get("alert_severity", "medium"),
                "message": action.get("reasoning", "")[:200],
                "technique": action.get("technique_id", ""),
                "source": action.get("action_name", "blue_response"),
            })

        # Firewall rules
        for rule in details.get("new_rules", []):
            self.network_state.add_firewall_block(str(rule))

        # Host isolation
        for hostname in details.get("isolated_hosts", []):
            self.network_state.isolate_host(hostname)

        return detected

    def _compute_scores(self) -> dict:
        red_score = sum(
            2 if h.compromise_status == "owned" else 1
            for h in self.network_state.hosts.values()
            if h.compromise_status != "none"
        )
        blue_score = len(self.network_state.alerts) + len(self.network_state.firewall_blocks)
        isolated = sum(1 for h in self.network_state.hosts.values() if h.is_isolated)
        return {
            "red": red_score,
            "blue": blue_score,
            "red_detail": {
                "compromised_hosts": sum(1 for h in self.network_state.hosts.values() if h.compromise_status != "none"),
                "total_actions": self._turn,
            },
            "blue_detail": {
                "alerts_raised": len(self.network_state.alerts),
                "blocks_applied": len(self.network_state.firewall_blocks),
                "hosts_isolated": isolated,
            },
        }

    def _win_reason(self, winner: str) -> str:
        if winner == "red_wins":
            return "Domain Controller compromised — Active Directory fully owned"
        if winner == "blue_wins":
            return "All intrusion attempts detected and contained — network secured"
        return "Maximum turns reached"
