import { useState, useEffect, useRef, useCallback } from 'react'
import {
  getConfig,
  updateConfig,
  startSimulation,
  stopSimulation,
  resetSimulation,
  getEventsUrl,
  type BackendConfig,
} from '../api/client'

// ── Types ─────────────────────────────────────────────────────────────────

export interface AgentAction {
  turn: number
  agent?: string
  agent_name?: string   // backend field
  team?: string
  agent_team?: string   // backend field
  action_name?: string
  technique?: string
  technique_id?: string
  target?: string
  result?: string
  reasoning?: string
  next_intent?: string
  confidence?: number
  details?: Record<string, unknown>
  alert_triggered?: boolean
  alert_severity?: string
}

export interface HostState {
  hostname: string
  ip: string
  os?: string
  services?: unknown[]
  patch_level?: number
  vulnerabilities?: unknown[]
  compromise_status: string
  is_isolated: boolean
  firewall_rules?: unknown[]
}

export interface NetworkState {
  hosts: Record<string, HostState>
  alerts: unknown[]
  turn: number           // backend field name
  turn_counter?: number  // alias
  game_status: string
  firewall_blocks?: string[]
}

export interface SimState {
  config: BackendConfig | null
  networkState: NetworkState | null
  events: AgentAction[]
  redThoughts: string[]
  blueThoughts: string[]
  isRunning: boolean
  isPaused: boolean
  isConnected: boolean
  error: string | null
  gameStatus: string
  turn: number
}

export interface UseSimulationReturn extends SimState {
  start: () => Promise<void>
  stop: () => Promise<void>
  reset: () => Promise<void>
  applyConfig: (patch: Partial<BackendConfig>) => Promise<void>
  clearError: () => void
}

// ── Hook ──────────────────────────────────────────────────────────────────

export function useSimulation(): UseSimulationReturn {
  const [state, setState] = useState<SimState>({
    config: null,
    networkState: null,
    events: [],
    redThoughts: [],
    blueThoughts: [],
    isRunning: false,
    isPaused: false,
    isConnected: false,
    error: null,
    gameStatus: 'idle',
    turn: 0,
  })

  const esRef = useRef<EventSource | null>(null)

  // Load initial config on mount
  useEffect(() => {
    getConfig()
      .then((cfg) => setState((s) => ({ ...s, config: cfg })))
      .catch(() => {/* backend not yet ready */})
  }, [])

  // Connect to SSE stream
  const connectSSE = useCallback(() => {
    if (esRef.current) {
      esRef.current.close()
    }

    const es = new EventSource(getEventsUrl())
    esRef.current = es

    es.onopen = () => setState((s) => ({ ...s, isConnected: true, error: null }))

    es.onerror = () => {
      // EventSource auto-reconnects — don't close it or mark disconnected immediately.
      // Only mark disconnected if the readyState is CLOSED (won't reconnect).
      if (es.readyState === EventSource.CLOSED) {
        setState((s) => ({ ...s, isConnected: false }))
        setTimeout(connectSSE, 3000)
      }
    }

    es.onmessage = (ev) => {
      // Mark connected on first message (handles proxies that don't fire onopen)
      setState((s) => ({ ...s, isConnected: true }))

      let payload: Record<string, unknown>
      try {
        payload = JSON.parse(ev.data)
      } catch {
        return
      }

      const event = payload.event as string

      if (event === 'agent_action') {
        const action = payload.data as AgentAction
        // backend uses agent_team; normalize to team
        const team = action.agent_team ?? action.team ?? ''
        const normalizedAction = { ...action, team }
        const thought = `[T${action.turn ?? '?'}] ${action.action_name ?? '?'} → ${action.target ?? '?'} (${action.result ?? '?'})`
        const reasoning = action.reasoning ?? ''

        setState((s) => {
          const newEvents = [...s.events, normalizedAction].slice(-100)
          const isRed = team === 'red'
          const newThoughts = isRed
            ? [...s.redThoughts, reasoning || thought].slice(-30)
            : [...s.blueThoughts, reasoning || thought].slice(-30)
          return {
            ...s,
            events: newEvents,
            redThoughts: isRed ? newThoughts : s.redThoughts,
            blueThoughts: isRed ? s.blueThoughts : newThoughts,
          }
        })
      }

      else if (event === 'network_state') {
        const data = payload.data as NetworkState
        setState((s) => ({
          ...s,
          networkState: data,
          gameStatus: data.game_status ?? s.gameStatus,
          turn: data.turn ?? data.turn_counter ?? s.turn,
        }))
      }

      else if (event === 'simulation_started') {
        setState((s) => ({ ...s, isRunning: true, gameStatus: 'running', error: null }))
      }

      else if (event === 'simulation_ended') {
        const status = (payload.status as string) ?? 'finished'
        setState((s) => ({ ...s, isRunning: false, gameStatus: status }))
      }

      else if (event === 'simulation_reset') {
        setState((s) => ({
          ...s,
          events: [],
          redThoughts: [],
          blueThoughts: [],
          networkState: null,
          isRunning: false,
          gameStatus: 'idle',
          turn: 0,
        }))
      }

      else if (event === 'agent_error') {
        const msg = `Agent error [${payload.agent}]: ${payload.error}`
        setState((s) => ({ ...s, error: msg }))
      }
    }
  }, [])

  // Connect SSE once on mount
  useEffect(() => {
    connectSSE()
    return () => esRef.current?.close()
  }, [connectSSE])

  // ── Actions ─────────────────────────────────────────────────────────────

  const start = useCallback(async () => {
    try {
      await startSimulation()
      setState((s) => ({ ...s, isRunning: true, error: null }))
    } catch (e) {
      setState((s) => ({ ...s, error: String(e) }))
    }
  }, [])

  const stop = useCallback(async () => {
    try {
      await stopSimulation()
      setState((s) => ({ ...s, isRunning: false }))
    } catch (e) {
      setState((s) => ({ ...s, error: String(e) }))
    }
  }, [])

  const reset = useCallback(async () => {
    try {
      await resetSimulation()
      // state update handled by SSE 'simulation_reset' event
    } catch (e) {
      setState((s) => ({ ...s, error: String(e) }))
    }
  }, [])

  const applyConfig = useCallback(async (patch: Partial<BackendConfig>) => {
    try {
      const res = await updateConfig(patch)
      setState((s) => ({ ...s, config: res.config }))
    } catch (e) {
      setState((s) => ({ ...s, error: String(e) }))
    }
  }, [])

  const clearError = useCallback(() => setState((s) => ({ ...s, error: null })), [])

  return { ...state, start, stop, reset, applyConfig, clearError }
}
