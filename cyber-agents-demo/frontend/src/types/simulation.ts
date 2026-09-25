export interface Host {
  ip: string
  hostname: string
  os: string
  services: string[]
  patch_level: number
  vulnerabilities: Vulnerability[]
  compromise_status: 'none' | 'foothold' | 'owned' | 'clean' | 'compromised' | 'partially_compromised'
  firewall_rules: FirewallRule[]
  is_isolated: boolean
}

export interface Vulnerability {
  cve_id: string
  name: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  cvss_score: number
  is_patched: boolean
}

export interface FirewallRule {
  direction: 'inbound' | 'outbound'
  protocol: string
  port: number | null
  action: 'allow' | 'deny'
  source?: string
  destination?: string
}

export interface Alert {
  id: string
  timestamp: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  message: string
  source_ip?: string
  target_ip?: string
  technique_id?: string
  is_acknowledged: boolean
}

export interface NetworkState {
  hosts: Record<string, Host>
  alerts: Alert[]
  turn: number
  game_status: 'idle' | 'running' | 'paused' | 'finished'
  scores: {
    red: number
    blue: number
  }
}

export interface ActionDetail {
  technique: string
  technique_id: string
  target: string
  result: 'success' | 'failure' | 'partial' | 'detected'
  reasoning: string
  next_intent: string
  confidence: number
  details: Record<string, unknown>
}

export interface AgentEvent {
  type: 'action' | 'detection' | 'response' | 'status' | 'game_over'
  team: 'red' | 'blue'
  agent: string
  turn: number
  action: ActionDetail
  network_state: NetworkState
  scores: {
    red: number
    blue: number
  }
  timestamp: string
}

export interface SimulationConfig {
  stack: 'proprietary' | 'opensource'
  scenario: string
  aggression: number
  detection_sensitivity: number
  speed_ms: number
}

export interface Stack {
  name: string
  model: string
  provider: string
  is_free: boolean
}

export interface Scenario {
  id: string
  name: string
  description: string
  difficulty: 'easy' | 'medium' | 'hard'
  num_hosts: number
  tags: string[]
}
