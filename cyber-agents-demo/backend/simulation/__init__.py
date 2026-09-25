"""
Simulation package for the cyber-agents-demo project.

This package contains the core simulation engine that orchestrates Red Team and
Blue Team agents across multiple turns, maintains network state, resolves action
outcomes, and emits structured events consumed by the WebSocket API and the
demo dashboard.

Modules (to be added)
---------------------
engine.py          – SimulationEngine: turn loop, state machine, event bus
network_state.py   – NetworkState: mutable network topology and host model
action_resolver.py – ActionResolver: maps AgentAction outcomes to state changes
event_bus.py       – EventBus: async pub/sub for real-time dashboard updates
scenarios/         – pre-built scenario definitions (JSON/YAML)
"""
