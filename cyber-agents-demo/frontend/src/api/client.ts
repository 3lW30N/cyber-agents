// In dev (local or Docker), browser uses relative URLs — Vite proxy forwards to backend.
// In production, set VITE_API_URL at build time to the absolute backend URL (e.g. Render).
const BASE = (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/$/, '') ?? ''

async function post<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`POST ${path} → ${res.status}: ${text}`)
  }
  return res.json()
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`)
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`GET ${path} → ${res.status}: ${text}`)
  }
  return res.json()
}

// ── Config / metadata ─────────────────────────────────────────────────────

export interface BackendConfig {
  stack: 'proprietary' | 'opensource'
  red_model: string
  blue_model: string
  temperature: number
  max_tokens: number
  turn_delay: number
  max_turns: number
  red_agents_enabled: string[]
  blue_agents_enabled: string[]
  verbose: boolean
}

export function getConfig(): Promise<BackendConfig> {
  return get<BackendConfig>('/config')
}

export function updateConfig(patch: Partial<BackendConfig>): Promise<{ status: string; config: BackendConfig }> {
  return post('/config', patch)
}

// ── Simulation control ────────────────────────────────────────────────────

export function startSimulation(): Promise<{ status: string; turn: number }> {
  return post('/simulation/start')
}

export function stopSimulation(): Promise<{ status: string; turn: number }> {
  return post('/simulation/stop')
}

export function resetSimulation(): Promise<{ status: string }> {
  return post('/simulation/reset')
}

export function getSimulationState(): Promise<unknown> {
  return get('/simulation/state')
}

// ── SSE stream URL ────────────────────────────────────────────────────────

export function getEventsUrl(): string {
  return `${BASE}/events`
}

// ── Agents / network ─────────────────────────────────────────────────────

export function getAgents(): Promise<unknown> {
  return get('/agents')
}

export function getNetwork(): Promise<unknown> {
  return get('/network')
}
