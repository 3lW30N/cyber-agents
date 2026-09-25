import React, { useEffect, useState, useRef } from "react";
import type { AgentEvent } from "./AttackTimeline";

interface AgentThoughtsProps {
  events: AgentEvent[]; // last ~5 events with reasoning
  activeAgent: string | null;
}

function useTypewriter(text: string, speed = 18, active = true) {
  const [displayed, setDisplayed] = useState("");
  const prevText = useRef("");

  useEffect(() => {
    if (!active) {
      setDisplayed(text);
      return;
    }
    if (text === prevText.current) return;
    prevText.current = text;
    setDisplayed("");
    let i = 0;
    const interval = setInterval(() => {
      i++;
      setDisplayed(text.slice(0, i));
      if (i >= text.length) clearInterval(interval);
    }, speed);
    return () => clearInterval(interval);
  }, [text, speed, active]);

  return displayed;
}

const ConfidenceMeter: React.FC<{
  value: number;
  team: "red" | "blue";
}> = ({ value, team }) => {
  const color = team === "red" ? "#ef4444" : "#3b82f6";
  const glow = team === "red" ? "rgba(239,68,68,0.5)" : "rgba(59,130,246,0.5)";
  const label =
    value >= 85
      ? "HIGH"
      : value >= 60
      ? "MEDIUM"
      : value >= 35
      ? "LOW"
      : "UNCERTAIN";

  return (
    <div className="flex items-center gap-2">
      <span className="text-[10px] text-gray-500 w-14 shrink-0 font-mono">
        Confidence
      </span>
      <div
        className="flex-1 h-1.5 rounded-full overflow-hidden"
        style={{ background: "#1e2a45" }}
      >
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{
            width: `${value}%`,
            background: `linear-gradient(90deg, ${color}99, ${color})`,
            boxShadow: `0 0 6px ${glow}`,
          }}
        />
      </div>
      <span
        className="text-[10px] font-bold font-mono w-16 text-right"
        style={{ color }}
      >
        {value}% {label}
      </span>
    </div>
  );
};

const ThinkingDots: React.FC = () => {
  const [dots, setDots] = useState(1);
  useEffect(() => {
    const t = setInterval(() => setDots((d) => (d % 3) + 1), 500);
    return () => clearInterval(t);
  }, []);
  return (
    <span className="text-gray-500">
      {".".repeat(dots)}
      {"  ".repeat(3 - dots)}
    </span>
  );
};

const AgentCard: React.FC<{
  event: AgentEvent;
  isLatest: boolean;
  isActiveAgent: boolean;
}> = ({ event, isLatest, isActiveAgent }) => {
  const [expanded, setExpanded] = useState(isLatest);
  const reasoning = event.reasoning ?? "(no reasoning captured)";
  const typedReasoning = useTypewriter(
    reasoning,
    14,
    isLatest && isActiveAgent
  );

  const teamColor = event.team === "red" ? "#ef4444" : "#3b82f6";
  const teamGlow =
    event.team === "red"
      ? "rgba(239,68,68,0.15)"
      : "rgba(59,130,246,0.15)";
  const teamBg =
    event.team === "red"
      ? "rgba(239,68,68,0.07)"
      : "rgba(59,130,246,0.07)";
  const teamBorder =
    event.team === "red"
      ? "rgba(239,68,68,0.35)"
      : "rgba(59,130,246,0.35)";

  const agentIcon = event.team === "red" ? "💀" : "🛡";
  const ts = new Date(event.timestamp).toLocaleTimeString("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

  return (
    <div
      className="rounded-xl p-3 mb-3 transition-all"
      style={{
        background: isLatest ? teamBg : "rgba(255,255,255,0.015)",
        border: `1px solid ${isLatest ? teamBorder : "#1e2a45"}`,
        boxShadow: isLatest ? `0 0 18px ${teamGlow}` : "none",
        opacity: isLatest ? 1 : 0.65,
      }}
    >
      {/* Agent header */}
      <div className="flex items-center gap-2 mb-2">
        <span
          className="text-xl"
          style={{
            filter: isLatest
              ? `drop-shadow(0 0 6px ${teamColor})`
              : "none",
          }}
        >
          {agentIcon}
        </span>
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <span
              className="text-sm font-bold font-mono"
              style={{ color: isLatest ? teamColor : "#6b7280" }}
            >
              {event.agentName}
            </span>
            <span
              className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider"
              style={{
                background:
                  event.team === "red"
                    ? "rgba(239,68,68,0.2)"
                    : "rgba(59,130,246,0.2)",
                border: `1px solid ${teamColor}50`,
                color: teamColor,
              }}
            >
              {event.team} team
            </span>
            {isLatest && isActiveAgent && (
              <span
                className="text-[10px] font-mono"
                style={{ color: teamColor }}
              >
                THINKING
                <ThinkingDots />
              </span>
            )}
          </div>
          <p className="text-[9px] text-gray-600 font-mono mt-0.5">
            {ts}
            {event.technique ? ` · ${event.technique}` : ""}
            {event.target ? ` · ${event.target}` : ""}
          </p>
        </div>
        <button
          className="text-[9px] text-gray-600 hover:text-gray-400 transition-colors px-2 py-1"
          onClick={() => setExpanded((v) => !v)}
        >
          {expanded ? "▲" : "▼"}
        </button>
      </div>

      {/* Summary */}
      <p className="text-xs text-gray-300 mb-2 leading-relaxed">
        {event.summary}
      </p>

      {/* Confidence */}
      {event.confidence !== undefined && (
        <div className="mb-2">
          <ConfidenceMeter value={event.confidence} team={event.team} />
        </div>
      )}

      {/* Chain of Thought */}
      {expanded && (
        <div
          className="rounded-lg p-2.5 mb-2"
          style={{
            background: "rgba(0,0,0,0.35)",
            border: "1px solid #0f1729",
          }}
        >
          <p
            className="text-[9px] font-bold uppercase tracking-widest mb-1.5"
            style={{ color: teamColor, fontFamily: "monospace" }}
          >
            Chain of Thought
          </p>
          <p
            className="text-[11px] font-mono leading-relaxed text-gray-400"
            style={{ whiteSpace: "pre-wrap" }}
          >
            {isLatest && isActiveAgent ? typedReasoning : reasoning}
            {isLatest && isActiveAgent && typedReasoning.length < reasoning.length && (
              <span
                className="inline-block w-1.5 h-3 bg-current ml-0.5"
                style={{
                  animation: "cursor 0.7s step-end infinite",
                  verticalAlign: "middle",
                  color: teamColor,
                }}
              />
            )}
          </p>
        </div>
      )}

      {/* Next intent */}
      {expanded && event.nextIntent && (
        <div
          className="rounded p-2 flex gap-2 items-start"
          style={{
            background: "rgba(255,255,255,0.02)",
            border: "1px solid #1e2a45",
          }}
        >
          <span className="text-[10px] text-gray-600 font-mono shrink-0">
            NEXT →
          </span>
          <p className="text-[10px] font-mono text-yellow-300">
            {event.nextIntent}
          </p>
        </div>
      )}
    </div>
  );
};

export const AgentThoughts: React.FC<AgentThoughtsProps> = ({
  events,
  activeAgent,
}) => {
  const recent = [...events].slice(0, 5).reverse();
  const latestEvent = recent[recent.length - 1];

  return (
    <div
      className="flex flex-col h-full"
      style={{
        background: "#090d19",
        border: "1px solid #1a2236",
        borderRadius: 12,
      }}
    >
      {/* Header */}
      <div
        className="flex items-center gap-2 px-4 py-2.5 shrink-0"
        style={{ borderBottom: "1px solid #141c2e" }}
      >
        <span className="text-base">🧠</span>
        <h2
          className="text-xs font-bold tracking-widest uppercase text-white"
          style={{ fontFamily: "monospace" }}
        >
          LLM Reasoning
        </h2>
        {activeAgent && (
          <span
            className="text-[10px] font-mono px-2 py-0.5 rounded ml-2"
            style={{
              background: "rgba(168,85,247,0.15)",
              border: "1px solid rgba(168,85,247,0.4)",
              color: "#c084fc",
              animation: "fadeInOut 2s ease-in-out infinite",
            }}
          >
            {activeAgent} is thinking...
          </span>
        )}
        <span className="ml-auto text-[9px] text-gray-600 font-mono">
          Last {recent.length} agents
        </span>
      </div>

      {/* Agents list */}
      <div className="flex-1 overflow-y-auto p-3">
        {recent.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-3 opacity-40">
            <span className="text-3xl">🧠</span>
            <p className="text-xs text-gray-500 text-center font-mono">
              No agent reasoning yet.
              <br />
              Start the simulation.
            </p>
          </div>
        ) : (
          recent.map((event, idx) => (
            <AgentCard
              key={event.id}
              event={event}
              isLatest={idx === recent.length - 1}
              isActiveAgent={
                activeAgent !== null && event.agentName === activeAgent
              }
            />
          ))
        )}
      </div>

      <style>{`
        @keyframes cursor {
          0%, 100% { opacity: 1; }
          50% { opacity: 0; }
        }
        @keyframes fadeInOut {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
      `}</style>
    </div>
  );
};

export default AgentThoughts;
