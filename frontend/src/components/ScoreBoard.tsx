import React from "react";

export type GameStatusType =
  | "idle"
  | "running"
  | "paused"
  | "red_wins"
  | "blue_wins"
  | "draw";

export interface Scores {
  red: {
    compromisedHosts: number;
    dataExfiltrated: number; // GB
    privilegeEscalations: number;
  };
  blue: {
    blockedAttacks: number;
    detectedIOCs: number;
    patchedVulns: number;
  };
}

interface ScoreBoardProps {
  scores: Scores;
  turn: number;
  maxTurns: number;
  gameStatus: GameStatusType;
}

const statusConfig: Record<
  GameStatusType,
  { label: string; color: string; bg: string; glow: string }
> = {
  idle: {
    label: "STANDBY",
    color: "#6b7280",
    bg: "rgba(107,114,128,0.15)",
    glow: "none",
  },
  running: {
    label: "● RUNNING",
    color: "#22c55e",
    bg: "rgba(34,197,94,0.12)",
    glow: "0 0 16px rgba(34,197,94,0.4)",
  },
  paused: {
    label: "⏸ PAUSED",
    color: "#eab308",
    bg: "rgba(234,179,8,0.12)",
    glow: "0 0 16px rgba(234,179,8,0.3)",
  },
  red_wins: {
    label: "💀 RED WINS",
    color: "#ef4444",
    bg: "rgba(239,68,68,0.18)",
    glow: "0 0 20px rgba(239,68,68,0.6)",
  },
  blue_wins: {
    label: "🛡 BLUE WINS",
    color: "#3b82f6",
    bg: "rgba(59,130,246,0.18)",
    glow: "0 0 20px rgba(59,130,246,0.6)",
  },
  draw: {
    label: "⚖ DRAW",
    color: "#a855f7",
    bg: "rgba(168,85,247,0.12)",
    glow: "0 0 16px rgba(168,85,247,0.3)",
  },
};

export const ScoreBoard: React.FC<ScoreBoardProps> = ({
  scores,
  turn,
  maxTurns,
  gameStatus,
}) => {
  const status = statusConfig[gameStatus];
  const progress = maxTurns > 0 ? (turn / maxTurns) * 100 : 0;

  // Win thresholds (configurable — shown as progress)
  const redWinThreshold = 6; // hosts compromised
  const blueWinThreshold = 15; // attacks blocked

  const redProgress = Math.min(
    (scores.red.compromisedHosts / redWinThreshold) * 100,
    100
  );
  const blueProgress = Math.min(
    (scores.blue.blockedAttacks / blueWinThreshold) * 100,
    100
  );

  return (
    <header
      className="flex items-center gap-4 px-5 py-3 shrink-0"
      style={{
        background: "rgba(10,14,26,0.95)",
        borderBottom: "1px solid #1e2a45",
        backdropFilter: "blur(12px)",
        zIndex: 10,
      }}
    >
      {/* Red Team Score Block */}
      <div
        className="flex items-center gap-3 rounded-xl px-4 py-2 min-w-[200px]"
        style={{
          background: "rgba(239,68,68,0.08)",
          border: "1px solid rgba(239,68,68,0.3)",
          boxShadow: "0 0 14px rgba(239,68,68,0.2)",
        }}
      >
        <span
          className="text-2xl"
          style={{ filter: "drop-shadow(0 0 6px rgba(239,68,68,0.8))" }}
        >
          💀
        </span>
        <div>
          <p
            className="text-xs font-bold uppercase tracking-widest"
            style={{ color: "#ef4444", fontFamily: "monospace" }}
          >
            Red Team
          </p>
          <div className="flex gap-3 mt-0.5">
            <div className="text-center">
              <p
                className="text-lg font-bold leading-none"
                style={{ color: "#fca5a5", fontFamily: "monospace" }}
              >
                {scores.red.compromisedHosts}
              </p>
              <p className="text-[9px] text-red-700 uppercase">hosts</p>
            </div>
            <div className="text-center">
              <p
                className="text-lg font-bold leading-none"
                style={{ color: "#fca5a5", fontFamily: "monospace" }}
              >
                {scores.red.dataExfiltrated.toFixed(1)}
              </p>
              <p className="text-[9px] text-red-700 uppercase">GB exfil</p>
            </div>
            <div className="text-center">
              <p
                className="text-lg font-bold leading-none"
                style={{ color: "#fca5a5", fontFamily: "monospace" }}
              >
                {scores.red.privilegeEscalations}
              </p>
              <p className="text-[9px] text-red-700 uppercase">privesc</p>
            </div>
          </div>
          {/* Red win condition bar */}
          <div className="mt-1.5">
            <div
              className="w-full h-1 rounded-full overflow-hidden"
              style={{ background: "rgba(239,68,68,0.15)" }}
            >
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{
                  width: `${redProgress}%`,
                  background: "linear-gradient(90deg, #ef4444, #dc2626)",
                  boxShadow: redProgress > 80 ? "0 0 8px #ef4444" : "none",
                }}
              />
            </div>
            <p className="text-[9px] text-red-700 mt-0.5">
              Win: {scores.red.compromisedHosts}/{redWinThreshold} hosts
            </p>
          </div>
        </div>
      </div>

      {/* Center — Turn Progress + Status */}
      <div className="flex-1 flex flex-col items-center gap-2">
        {/* Status Badge */}
        <div
          className="px-4 py-1 rounded-full font-bold text-sm tracking-widest uppercase"
          style={{
            background: status.bg,
            border: `1px solid ${status.color}`,
            color: status.color,
            boxShadow: status.glow,
            fontFamily: "monospace",
            letterSpacing: "0.18em",
            animation:
              gameStatus === "running" ? "statusPulse 2s infinite" : "none",
          }}
        >
          {status.label}
        </div>

        {/* Turn counter */}
        <div className="flex items-center gap-2 w-full max-w-xs">
          <span
            className="text-xs text-gray-500 font-mono shrink-0"
          >
            Turn {turn}
          </span>
          <div
            className="flex-1 h-2 rounded-full overflow-hidden relative"
            style={{ background: "#1e2a45" }}
          >
            <div
              className="h-full rounded-full transition-all duration-700"
              style={{
                width: `${progress}%`,
                background:
                  progress < 50
                    ? "linear-gradient(90deg, #22c55e, #16a34a)"
                    : progress < 80
                    ? "linear-gradient(90deg, #eab308, #ca8a04)"
                    : "linear-gradient(90deg, #ef4444, #b91c1c)",
              }}
            />
          </div>
          <span className="text-xs text-gray-500 font-mono shrink-0">
            {maxTurns}
          </span>
        </div>
      </div>

      {/* Blue Team Score Block */}
      <div
        className="flex items-center gap-3 rounded-xl px-4 py-2 min-w-[200px] justify-end"
        style={{
          background: "rgba(59,130,246,0.08)",
          border: "1px solid rgba(59,130,246,0.3)",
          boxShadow: "0 0 14px rgba(59,130,246,0.2)",
        }}
      >
        <div className="text-right">
          <p
            className="text-xs font-bold uppercase tracking-widest"
            style={{ color: "#3b82f6", fontFamily: "monospace" }}
          >
            Blue Team
          </p>
          <div className="flex gap-3 mt-0.5 justify-end">
            <div className="text-center">
              <p
                className="text-lg font-bold leading-none"
                style={{ color: "#93c5fd", fontFamily: "monospace" }}
              >
                {scores.blue.blockedAttacks}
              </p>
              <p className="text-[9px] text-blue-700 uppercase">blocked</p>
            </div>
            <div className="text-center">
              <p
                className="text-lg font-bold leading-none"
                style={{ color: "#93c5fd", fontFamily: "monospace" }}
              >
                {scores.blue.detectedIOCs}
              </p>
              <p className="text-[9px] text-blue-700 uppercase">IOCs</p>
            </div>
            <div className="text-center">
              <p
                className="text-lg font-bold leading-none"
                style={{ color: "#93c5fd", fontFamily: "monospace" }}
              >
                {scores.blue.patchedVulns}
              </p>
              <p className="text-[9px] text-blue-700 uppercase">patched</p>
            </div>
          </div>
          {/* Blue win condition bar */}
          <div className="mt-1.5">
            <div
              className="w-full h-1 rounded-full overflow-hidden"
              style={{ background: "rgba(59,130,246,0.15)" }}
            >
              <div
                className="h-full rounded-full transition-all duration-500 ml-auto"
                style={{
                  width: `${blueProgress}%`,
                  background: "linear-gradient(90deg, #1d4ed8, #3b82f6)",
                  boxShadow: blueProgress > 80 ? "0 0 8px #3b82f6" : "none",
                }}
              />
            </div>
            <p className="text-[9px] text-blue-700 mt-0.5 text-right">
              Win: {scores.blue.blockedAttacks}/{blueWinThreshold} blocked
            </p>
          </div>
        </div>
        <span
          className="text-2xl"
          style={{ filter: "drop-shadow(0 0 6px rgba(59,130,246,0.8))" }}
        >
          🛡
        </span>
      </div>

      <style>{`
        @keyframes statusPulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.7; }
        }
      `}</style>
    </header>
  );
};

export default ScoreBoard;
