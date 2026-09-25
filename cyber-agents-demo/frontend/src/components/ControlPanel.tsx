import React from "react";

export interface AgentConfig {
  stack: "proprietary" | "opensource";
  scenario: string;
  aggression: number;
  detectionSensitivity: number;
  simulationSpeed: number; // ms delay between turns
}

export interface GameStatus {
  phase: string;
  compromisedHosts: number;
  totalHosts: number;
  blockedAttacks: number;
  detectedIOCs: number;
  winner: "red" | "blue" | null;
}

interface ControlPanelProps {
  config: AgentConfig;
  onConfigChange: (config: AgentConfig) => void;
  onStart: () => void;
  onPause: () => void;
  onResume: () => void;
  onReset: () => void;
  isRunning: boolean;
  isPaused: boolean;
  gameStatus: GameStatus;
  turn: number;
  maxTurns: number;
}

const scenarios = [
  { value: "network_intrusion", label: "Network Intrusion" },
  { value: "ransomware_attack", label: "Ransomware Attack" },
  { value: "apt_campaign", label: "APT Campaign" },
  { value: "supply_chain", label: "Supply Chain Attack" },
  { value: "insider_threat", label: "Insider Threat" },
];

export const ControlPanel: React.FC<ControlPanelProps> = ({
  config,
  onConfigChange,
  onStart,
  onPause,
  onResume,
  onReset,
  isRunning,
  isPaused,
  gameStatus,
  turn,
  maxTurns,
}) => {
  const update = (partial: Partial<AgentConfig>) =>
    onConfigChange({ ...config, ...partial });

  const speedLabel = (ms: number) => {
    if (ms >= 4500) return "Very Slow";
    if (ms >= 3500) return "Slow";
    if (ms >= 2500) return "Medium";
    if (ms >= 1500) return "Fast";
    return "Very Fast";
  };

  const phaseColor: Record<string, string> = {
    reconnaissance: "text-yellow-400",
    exploitation: "text-red-400",
    persistence: "text-orange-400",
    defense: "text-blue-400",
    containment: "text-cyan-400",
    idle: "text-gray-400",
  };

  return (
    <aside
      className="flex flex-col gap-4 h-full overflow-y-auto p-4"
      style={{
        width: 280,
        minWidth: 260,
        background: "#0d1120",
        borderRight: "1px solid #1e2a45",
      }}
    >
      {/* Header */}
      <div className="flex items-center gap-2 mb-1">
        {isRunning && !isPaused && (
          <span
            className="inline-block w-2.5 h-2.5 rounded-full bg-green-400"
            style={{ animation: "pulse 1s infinite" }}
          />
        )}
        {isPaused && (
          <span className="inline-block w-2.5 h-2.5 rounded-full bg-yellow-400" />
        )}
        {!isRunning && (
          <span className="inline-block w-2.5 h-2.5 rounded-full bg-gray-600" />
        )}
        <h1
          className="text-sm font-bold tracking-widest text-white uppercase"
          style={{ fontFamily: "monospace", letterSpacing: "0.2em" }}
        >
          Cyber Agents Demo
        </h1>
      </div>

      {/* Stack Selector */}
      <section>
        <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">
          Agent Stack
        </p>
        <div className="flex flex-col gap-2">
          {/* Proprietary */}
          <label
            className="cursor-pointer rounded-lg border p-3 flex gap-3 items-start transition-all"
            style={{
              borderColor:
                config.stack === "proprietary" ? "#ef4444" : "#1e2a45",
              background:
                config.stack === "proprietary"
                  ? "rgba(239,68,68,0.08)"
                  : "rgba(255,255,255,0.02)",
              boxShadow:
                config.stack === "proprietary"
                  ? "0 0 10px rgba(239,68,68,0.25)"
                  : "none",
            }}
          >
            <input
              type="radio"
              name="stack"
              value="proprietary"
              checked={config.stack === "proprietary"}
              onChange={() => update({ stack: "proprietary" })}
              className="mt-0.5 accent-red-500"
              disabled={isRunning && !isPaused}
            />
            <div className="flex-1">
              <div className="flex items-center gap-1.5">
                <span className="text-lg">⚡</span>
                <span className="text-sm font-semibold text-white">
                  Gemini 2.5 Flash
                </span>
              </div>
              <p className="text-xs text-gray-400 mt-0.5">Proprietary — Google</p>
              <span
                className="inline-block mt-1 px-1.5 py-0.5 rounded text-[10px] font-bold"
                style={{
                  background: "rgba(234,179,8,0.15)",
                  border: "1px solid rgba(234,179,8,0.4)",
                  color: "#eab308",
                }}
              >
                FREE TIER
              </span>
            </div>
          </label>

          {/* Open Source */}
          <label
            className="cursor-pointer rounded-lg border p-3 flex gap-3 items-start transition-all"
            style={{
              borderColor:
                config.stack === "opensource" ? "#3b82f6" : "#1e2a45",
              background:
                config.stack === "opensource"
                  ? "rgba(59,130,246,0.08)"
                  : "rgba(255,255,255,0.02)",
              boxShadow:
                config.stack === "opensource"
                  ? "0 0 10px rgba(59,130,246,0.25)"
                  : "none",
            }}
          >
            <input
              type="radio"
              name="stack"
              value="opensource"
              checked={config.stack === "opensource"}
              onChange={() => update({ stack: "opensource" })}
              className="mt-0.5 accent-blue-500"
              disabled={isRunning && !isPaused}
            />
            <div className="flex-1">
              <div className="flex items-center gap-1.5">
                <span className="text-lg">🦙</span>
                <span className="text-sm font-semibold text-white">
                  Groq Llama 3.1
                </span>
              </div>
              <p className="text-xs text-gray-400 mt-0.5">Open Source — Meta / Groq</p>
              <span
                className="inline-block mt-1 px-1.5 py-0.5 rounded text-[10px] font-bold"
                style={{
                  background: "rgba(34,197,94,0.15)",
                  border: "1px solid rgba(34,197,94,0.4)",
                  color: "#22c55e",
                }}
              >
                FREE TIER
              </span>
            </div>
          </label>
        </div>
      </section>

      {/* Scenario */}
      <section>
        <label className="text-xs text-gray-500 uppercase tracking-wider mb-1 block">
          Scenario
        </label>
        <select
          value={config.scenario}
          onChange={(e) => update({ scenario: e.target.value })}
          disabled={isRunning && !isPaused}
          className="w-full rounded-md px-2 py-1.5 text-sm text-white"
          style={{
            background: "#111827",
            border: "1px solid #1e2a45",
            fontFamily: "monospace",
          }}
        >
          {scenarios.map((s) => (
            <option key={s.value} value={s.value}>
              {s.label}
            </option>
          ))}
        </select>
      </section>

      {/* Sliders */}
      <section className="flex flex-col gap-4">
        {/* Aggression */}
        <div>
          <div className="flex justify-between items-center mb-1">
            <label className="text-xs text-gray-500 uppercase tracking-wider">
              Aggression Level
            </label>
            <span className="text-xs font-bold text-red-400 font-mono">
              {config.aggression}/10
            </span>
          </div>
          <input
            type="range"
            min={1}
            max={10}
            value={config.aggression}
            onChange={(e) => update({ aggression: Number(e.target.value) })}
            disabled={isRunning && !isPaused}
            className="w-full h-1.5 rounded cursor-pointer"
            style={{ accentColor: "#ef4444" }}
          />
          <div className="flex justify-between text-[10px] text-gray-600 mt-0.5">
            <span>Passive</span>
            <span>Destructive</span>
          </div>
        </div>

        {/* Detection Sensitivity */}
        <div>
          <div className="flex justify-between items-center mb-1">
            <label className="text-xs text-gray-500 uppercase tracking-wider">
              Detection Sensitivity
            </label>
            <span className="text-xs font-bold text-blue-400 font-mono">
              {config.detectionSensitivity}/10
            </span>
          </div>
          <input
            type="range"
            min={1}
            max={10}
            value={config.detectionSensitivity}
            onChange={(e) =>
              update({ detectionSensitivity: Number(e.target.value) })
            }
            disabled={isRunning && !isPaused}
            className="w-full h-1.5 rounded cursor-pointer"
            style={{ accentColor: "#3b82f6" }}
          />
          <div className="flex justify-between text-[10px] text-gray-600 mt-0.5">
            <span>Low</span>
            <span>Paranoid</span>
          </div>
        </div>

        {/* Simulation Speed */}
        <div>
          <div className="flex justify-between items-center mb-1">
            <label className="text-xs text-gray-500 uppercase tracking-wider">
              Simulation Speed
            </label>
            <span className="text-xs font-bold text-purple-400 font-mono">
              {speedLabel(config.simulationSpeed)}
            </span>
          </div>
          <input
            type="range"
            min={1000}
            max={5000}
            step={500}
            value={config.simulationSpeed}
            onChange={(e) =>
              update({ simulationSpeed: Number(e.target.value) })
            }
            className="w-full h-1.5 rounded cursor-pointer"
            style={{ accentColor: "#a855f7", direction: "rtl" }}
          />
          <div
            className="flex justify-between text-[10px] text-gray-600 mt-0.5"
            style={{ direction: "ltr" }}
          >
            <span>Slow (5s)</span>
            <span>Fast (1s)</span>
          </div>
        </div>
      </section>

      {/* Control Buttons */}
      <section className="flex flex-col gap-2">
        {!isRunning ? (
          <button
            onClick={onStart}
            className="w-full py-2 rounded-lg font-bold text-sm tracking-widest uppercase transition-all"
            style={{
              background: "rgba(34,197,94,0.15)",
              border: "1px solid #22c55e",
              color: "#22c55e",
              boxShadow: "0 0 12px rgba(34,197,94,0.2)",
              fontFamily: "monospace",
            }}
            onMouseEnter={(e) =>
              (e.currentTarget.style.boxShadow =
                "0 0 24px rgba(34,197,94,0.5)")
            }
            onMouseLeave={(e) =>
              (e.currentTarget.style.boxShadow =
                "0 0 12px rgba(34,197,94,0.2)")
            }
          >
            ▶ Start Simulation
          </button>
        ) : isPaused ? (
          <button
            onClick={onResume}
            className="w-full py-2 rounded-lg font-bold text-sm tracking-widest uppercase transition-all"
            style={{
              background: "rgba(34,197,94,0.15)",
              border: "1px solid #22c55e",
              color: "#22c55e",
              boxShadow: "0 0 12px rgba(34,197,94,0.2)",
              fontFamily: "monospace",
            }}
          >
            ▶ Resume
          </button>
        ) : (
          <button
            onClick={onPause}
            className="w-full py-2 rounded-lg font-bold text-sm tracking-widest uppercase transition-all"
            style={{
              background: "rgba(234,179,8,0.15)",
              border: "1px solid #eab308",
              color: "#eab308",
              boxShadow: "0 0 12px rgba(234,179,8,0.2)",
              fontFamily: "monospace",
            }}
          >
            ⏸ Pause
          </button>
        )}
        <button
          onClick={onReset}
          className="w-full py-2 rounded-lg font-bold text-sm tracking-widest uppercase transition-all"
          style={{
            background: "rgba(107,114,128,0.15)",
            border: "1px solid #4b5563",
            color: "#9ca3af",
            fontFamily: "monospace",
          }}
        >
          ↺ Reset
        </button>
      </section>

      {/* Game Status */}
      {isRunning && (
        <section
          className="rounded-lg p-3 flex flex-col gap-2"
          style={{ background: "rgba(255,255,255,0.02)", border: "1px solid #1e2a45" }}
        >
          <p className="text-xs text-gray-500 uppercase tracking-wider">
            Game Status
          </p>
          <div className="flex justify-between">
            <span className="text-xs text-gray-400">Turn</span>
            <span className="text-xs font-mono text-white">
              {turn} / {maxTurns}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-xs text-gray-400">Phase</span>
            <span
              className={`text-xs font-mono font-bold ${
                phaseColor[gameStatus.phase] ?? "text-gray-300"
              }`}
            >
              {gameStatus.phase.toUpperCase()}
            </span>
          </div>

          {/* Red progress */}
          <div>
            <div className="flex justify-between mb-0.5">
              <span className="text-[10px] text-red-400">Red — Compromised</span>
              <span className="text-[10px] font-mono text-red-300">
                {gameStatus.compromisedHosts}/{gameStatus.totalHosts}
              </span>
            </div>
            <div className="w-full h-1.5 rounded-full overflow-hidden" style={{ background: "#1e2a45" }}>
              <div
                className="h-full rounded-full transition-all"
                style={{
                  width: `${(gameStatus.compromisedHosts / Math.max(gameStatus.totalHosts, 1)) * 100}%`,
                  background: "linear-gradient(90deg, #ef4444, #b91c1c)",
                  boxShadow: "0 0 6px rgba(239,68,68,0.6)",
                }}
              />
            </div>
          </div>

          {/* Blue progress */}
          <div>
            <div className="flex justify-between mb-0.5">
              <span className="text-[10px] text-blue-400">Blue — Blocked</span>
              <span className="text-[10px] font-mono text-blue-300">
                {gameStatus.blockedAttacks}
              </span>
            </div>
            <div className="w-full h-1.5 rounded-full overflow-hidden" style={{ background: "#1e2a45" }}>
              <div
                className="h-full rounded-full transition-all"
                style={{
                  width: `${Math.min((gameStatus.blockedAttacks / Math.max(turn * 2, 1)) * 100, 100)}%`,
                  background: "linear-gradient(90deg, #3b82f6, #1d4ed8)",
                  boxShadow: "0 0 6px rgba(59,130,246,0.6)",
                }}
              />
            </div>
          </div>
        </section>
      )}

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.3; }
        }
      `}</style>
    </aside>
  );
};

export default ControlPanel;
