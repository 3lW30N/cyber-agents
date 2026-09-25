import { useState, useMemo } from 'react'
import { useSimulation, type AgentAction } from './hooks/useSimulation'
import NetworkMap from './components/NetworkMap'
import type { BackendConfig } from './api/client'

// ---------------------------------------------------------------------------
// ScoreBoard
// ---------------------------------------------------------------------------

function ScoreBoard({ redScore, blueScore, turn, gameStatus }: {
  redScore: number
  blueScore: number
  turn: number
  gameStatus: string
}) {
  const statusColor =
    gameStatus === 'red_wins' ? '#ef4444' : gameStatus === 'blue_wins' ? '#22c55e' : '#94a3b8'

  return (
    <div className="flex items-center justify-between px-4 py-2 bg-panel border border-slate-700 rounded text-sm">
      <div className="flex items-center gap-3">
        <span className="text-red-400 font-bold text-lg">{redScore}</span>
        <span className="text-slate-500">RED</span>
      </div>
      <div className="text-center">
        <div className="text-xs text-slate-500">TURN {turn}</div>
        <div style={{ color: statusColor }} className="text-xs font-semibold uppercase tracking-widest">
          {gameStatus === 'running' ? 'BATTLE'
            : gameStatus === 'red_wins' ? 'RED WINS'
            : gameStatus === 'blue_wins' ? 'BLUE WINS'
            : gameStatus.toUpperCase()}
        </div>
      </div>
      <div className="flex items-center gap-3">
        <span className="text-slate-500">BLUE</span>
        <span className="text-blue-400 font-bold text-lg">{blueScore}</span>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// AgentThoughts
// ---------------------------------------------------------------------------

function AgentThoughts({ redThoughts, blueThoughts }: {
  redThoughts: string[]
  blueThoughts: string[]
}) {
  const [tab, setTab] = useState<'red' | 'blue'>('red')
  const thoughts = tab === 'red' ? redThoughts : blueThoughts
  const color = tab === 'red' ? 'text-red-400' : 'text-blue-400'
  return (
    <div className="flex flex-col h-full bg-panel border border-slate-700 rounded overflow-hidden">
      <div className="flex border-b border-slate-700">
        <button
          className={`flex-1 py-2 text-xs font-semibold tracking-widest uppercase ${tab === 'red' ? 'bg-red-900/30 text-red-400' : 'text-slate-500 hover:text-slate-300'}`}
          onClick={() => setTab('red')}
        >
          Red Thoughts
        </button>
        <button
          className={`flex-1 py-2 text-xs font-semibold tracking-widest uppercase ${tab === 'blue' ? 'bg-blue-900/30 text-blue-400' : 'text-slate-500 hover:text-slate-300'}`}
          onClick={() => setTab('blue')}
        >
          Blue Thoughts
        </button>
      </div>
      <div className="flex flex-col-reverse flex-1 overflow-y-auto p-3 gap-1 font-mono">
        {thoughts.length === 0 ? (
          <div className="text-slate-600 text-xs italic">Waiting for agent activity...</div>
        ) : (
          thoughts.map((t, i) => (
            <div key={i} className={`text-xs ${color} leading-relaxed`}>
              {t}
            </div>
          ))
        )}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// AttackTimeline / DefenseLog
// ---------------------------------------------------------------------------

function AttackTimeline({ events }: { events: AgentAction[] }) {
  const redEvents = useMemo(
    () => events.filter((e) => e.team === 'red').slice(-40),
    [events]
  )
  return (
    <div className="flex flex-col h-full bg-panel border border-slate-700 rounded overflow-hidden">
      <div className="px-3 py-2 border-b border-slate-700 text-xs font-semibold text-red-400 tracking-widest uppercase">
        Attack Timeline
      </div>
      <div className="flex flex-col-reverse flex-1 overflow-y-auto p-2 gap-1">
        {redEvents.length === 0 ? (
          <div className="text-slate-600 text-xs italic p-2">No attacks yet...</div>
        ) : (
          redEvents.map((e, i) => (
            <div key={i} className="flex gap-2 text-xs border-b border-slate-800 pb-1">
              <span className="text-slate-500 shrink-0">{`T${e.turn}`}</span>
              <span className="text-slate-400 shrink-0">[{e.agent_name ?? e.agent ?? e.action_name}]</span>
              <span className="text-red-300">{e.technique ?? e.action_name}</span>
              {e.target && (
                <span className="text-slate-500 ml-auto shrink-0">{e.target}</span>
              )}
              <span className={`shrink-0 ${e.result === 'success' ? 'text-green-400' : e.result === 'failure' ? 'text-red-500' : 'text-yellow-400'}`}>
                {e.result ?? ''}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

function DefenseLog({ events }: { events: AgentAction[] }) {
  const blueEvents = useMemo(
    () => events.filter((e) => e.team === 'blue').slice(-40),
    [events]
  )
  return (
    <div className="flex flex-col h-full bg-panel border border-slate-700 rounded overflow-hidden">
      <div className="px-3 py-2 border-b border-slate-700 text-xs font-semibold text-blue-400 tracking-widest uppercase">
        Defense Log
      </div>
      <div className="flex flex-col-reverse flex-1 overflow-y-auto p-2 gap-1">
        {blueEvents.length === 0 ? (
          <div className="text-slate-600 text-xs italic p-2">No defense actions yet...</div>
        ) : (
          blueEvents.map((e, i) => (
            <div key={i} className="flex gap-2 text-xs border-b border-slate-800 pb-1">
              <span className="text-slate-500 shrink-0">{`T${e.turn}`}</span>
              <span className="text-slate-400 shrink-0">[{e.agent_name ?? e.agent ?? e.action_name}]</span>
              <span className="text-blue-300">{e.technique ?? e.action_name}</span>
              {e.target && (
                <span className="text-slate-500 ml-auto shrink-0">{e.target}</span>
              )}
              <span className={`shrink-0 ${e.result === 'success' ? 'text-green-400' : e.result === 'failure' ? 'text-red-500' : 'text-yellow-400'}`}>
                {e.result ?? ''}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// ControlPanel
// ---------------------------------------------------------------------------

const SCENARIOS = [
  { id: 'apt_simulation', name: 'APT Simulation', description: 'Advanced persistent threat attack on corporate network', difficulty: 'hard' },
  { id: 'ransomware_drill', name: 'Ransomware Drill', description: 'Ransomware infection and containment exercise', difficulty: 'medium' },
  { id: 'insider_threat', name: 'Insider Threat', description: 'Simulated insider exfiltration scenario', difficulty: 'easy' },
]

function ControlPanel({
  isRunning,
  isConnected,
  onStart,
  onStop,
  onReset,
  error,
  onClearError,
}: {
  isRunning: boolean
  isConnected: boolean
  onStart: (cfg: Partial<BackendConfig>) => void
  onStop: () => void
  onReset: () => void
  error: string | null
  onClearError: () => void
}) {
  const [stack, setStack] = useState<'proprietary' | 'opensource'>('proprietary')
  const [_scenario, setScenario] = useState('apt_simulation')
  const [speed, setSpeed] = useState(1500)

  const handleStart = () => {
    onStart({
      stack,
      turn_delay: speed / 1000,
    })
  }

  return (
    <div className="flex flex-col gap-4 p-4 bg-panel h-full overflow-y-auto border-r border-slate-700">
      <div className="text-xs font-bold text-slate-400 tracking-widest uppercase flex items-center gap-2">
        Configuration
        <span className={`w-2 h-2 rounded-full ml-auto ${isConnected ? 'bg-green-400' : 'bg-red-500 animate-pulse'}`} title={isConnected ? 'Backend connected' : 'Connecting...'} />
      </div>

      {/* Stack selector */}
      <div>
        <label className="block text-xs text-slate-500 mb-2 uppercase tracking-wider">LLM Stack</label>
        <div className="flex gap-2">
          {(['proprietary', 'opensource'] as const).map((s) => (
            <button
              key={s}
              onClick={() => setStack(s)}
              disabled={isRunning}
              className={`flex-1 py-2 text-xs rounded border transition-colors ${
                stack === s
                  ? s === 'proprietary'
                    ? 'bg-purple-900/40 border-purple-500 text-purple-300'
                    : 'bg-emerald-900/40 border-emerald-500 text-emerald-300'
                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
              }`}
            >
              {s === 'proprietary' ? 'Gemini' : 'Groq / Llama'}
            </button>
          ))}
        </div>
        <div className="text-xs text-slate-600 mt-1">
          {stack === 'proprietary' ? 'gemini-2.0-flash (free tier)' : 'llama-3.1-8b-instant (free)'}
        </div>
      </div>

      {/* Scenario selector */}
      <div>
        <label className="block text-xs text-slate-500 mb-2 uppercase tracking-wider">Scenario</label>
        <div className="flex flex-col gap-1">
          {SCENARIOS.map((s) => (
            <button
              key={s.id}
              onClick={() => setScenario(s.id)}
              disabled={isRunning}
              className={`text-left px-3 py-2 rounded border text-xs transition-colors ${
                _scenario === s.id
                  ? 'bg-slate-700 border-blue-500 text-blue-300'
                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
              }`}
            >
              <div className="font-semibold">{s.name}</div>
              <div className="text-slate-500 mt-0.5">{s.description}</div>
              <div className={`mt-0.5 font-mono text-xs ${s.difficulty === 'hard' ? 'text-red-400' : s.difficulty === 'medium' ? 'text-yellow-400' : 'text-green-400'}`}>
                {s.difficulty.toUpperCase()}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Speed slider */}
      <div>
        <label className="block text-xs text-slate-500 mb-1 uppercase tracking-wider">
          Speed <span className="text-slate-400">{speed / 1000}s / turn</span>
        </label>
        <input type="range" min={500} max={5000} step={500} value={speed} onChange={(e) => setSpeed(+e.target.value)}
          disabled={isRunning}
          className="w-full accent-slate-400" />
      </div>

      {/* Error */}
      {error && (
        <div className="bg-red-900/30 border border-red-700 rounded p-2 text-xs text-red-300 flex justify-between items-start gap-2">
          <span>{error}</span>
          <button onClick={onClearError} className="text-red-500 hover:text-red-300 shrink-0 text-base leading-none">x</button>
        </div>
      )}

      {/* Controls */}
      <div className="flex flex-col gap-2 mt-auto pt-2 border-t border-slate-700">
        {!isRunning ? (
          <button
            onClick={handleStart}
            disabled={!isConnected}
            className="w-full py-3 bg-gradient-to-r from-red-700 to-red-500 hover:from-red-600 hover:to-red-400 disabled:opacity-40 text-white rounded font-bold text-sm tracking-wider uppercase transition-all"
          >
            {isConnected ? 'Start Simulation' : 'Connecting…'}
          </button>
        ) : (
          <>
            <button onClick={onStop}
              className="w-full py-2 bg-yellow-700 hover:bg-yellow-600 text-white rounded text-sm font-semibold uppercase tracking-wider">
              Stop
            </button>
            <button onClick={onReset}
              className="w-full py-2 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded text-sm font-semibold uppercase tracking-wider">
              Reset
            </button>
          </>
        )}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------
export default function App() {
  const {
    networkState,
    events,
    isRunning,
    isConnected,
    redThoughts,
    blueThoughts,
    error,
    start,
    stop,
    reset,
    applyConfig,
    clearError,
    gameStatus,
    turn,
  } = useSimulation()

  const [rightTab, setRightTab] = useState<'attack' | 'defense'>('attack')

  // Compute scores from network state (red: hosts compromised, blue: hosts defended)
  const { redScore, blueScore } = useMemo(() => {
    if (!networkState?.hosts) return { redScore: 0, blueScore: 0 }
    const hosts = Object.values(networkState.hosts)
    const red = hosts.filter((h) => h.compromise_status === 'owned' || h.compromise_status === 'compromised').length
    const blue = hosts.filter((h) => h.is_isolated).length
    return { redScore: red, blueScore: blue }
  }, [networkState])

  const handleStart = async (patch: Partial<import('./api/client').BackendConfig>) => {
    await applyConfig(patch)
    await start()
  }

  return (
    <div
      className="flex flex-col h-screen text-slate-100 font-sans overflow-hidden"
      style={{ background: '#0a0e1a' }}
    >
      {/* Header */}
      <header className="flex items-center justify-between px-6 py-3 border-b border-slate-700 bg-slate-900/80 backdrop-blur shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-3 h-3 rounded-full bg-red-500 shadow-lg shadow-red-500/50" />
          <span className="text-sm font-bold tracking-widest text-slate-100 uppercase">
            Cyber Agents Demo
          </span>
          <span className="text-slate-600 font-light hidden sm:inline">|</span>
          <span className="text-sm font-semibold text-red-400 hidden sm:inline">Red Team</span>
          <span className="text-slate-600 hidden sm:inline">vs</span>
          <span className="text-sm font-semibold text-blue-400 hidden sm:inline">Blue Team</span>
        </div>
        <div className="flex items-center gap-4 text-xs">
          {isRunning && (
            <span className="flex items-center gap-1.5 text-green-400">
              <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
              LIVE
            </span>
          )}
          <span className="text-slate-500 hidden lg:inline">Turn {turn}</span>
        </div>
      </header>

      {/* Main layout */}
      <div className="flex flex-1 overflow-hidden flex-col lg:flex-row">
        {/* Left sidebar: ControlPanel */}
        <aside className="w-full lg:w-[280px] shrink-0 overflow-y-auto border-b lg:border-b-0 lg:border-r border-slate-700">
          <ControlPanel
            isRunning={isRunning}
            isConnected={isConnected}
            onStart={handleStart}
            onStop={stop}
            onReset={reset}
            error={error}
            onClearError={clearError}
          />
        </aside>

        {/* Center column */}
        <main className="flex flex-col flex-1 overflow-hidden min-w-0">
          {/* Network map (top 60%) */}
          <div className="flex-[3] min-h-[200px] flex flex-col overflow-hidden">
            <div className="flex-1 overflow-hidden">
              <NetworkMap
                networkState={networkState}
                events={events}
                activeEvent={events[events.length - 1] ?? null}
              />
            </div>
            {/* Scoreboard overlay at bottom of map area */}
            <div className="shrink-0 px-3 pb-2">
              <ScoreBoard redScore={redScore} blueScore={blueScore} turn={turn} gameStatus={gameStatus} />
            </div>
          </div>

          {/* Agent thoughts (bottom 40%) */}
          <div className="flex-[2] min-h-[120px] overflow-hidden border-t border-slate-700 p-2">
            <AgentThoughts redThoughts={redThoughts} blueThoughts={blueThoughts} />
          </div>
        </main>

        {/* Right panel: Attack Timeline / Defense Log */}
        <aside className="w-full lg:w-[320px] shrink-0 flex flex-col overflow-hidden border-t lg:border-t-0 lg:border-l border-slate-700">
          {/* Tab bar */}
          <div className="flex border-b border-slate-700 shrink-0">
            <button
              className={`flex-1 py-2 text-xs font-semibold tracking-widest uppercase transition-colors ${
                rightTab === 'attack' ? 'bg-red-900/30 text-red-400' : 'text-slate-500 hover:text-slate-300'
              }`}
              onClick={() => setRightTab('attack')}
            >
              Attacks
            </button>
            <button
              className={`flex-1 py-2 text-xs font-semibold tracking-widest uppercase transition-colors ${
                rightTab === 'defense' ? 'bg-blue-900/30 text-blue-400' : 'text-slate-500 hover:text-slate-300'
              }`}
              onClick={() => setRightTab('defense')}
            >
              Defenses
            </button>
          </div>
          <div className="flex-1 overflow-hidden">
            {rightTab === 'attack' ? (
              <AttackTimeline events={events} />
            ) : (
              <DefenseLog events={events} />
            )}
          </div>
        </aside>
      </div>
    </div>
  )
}
