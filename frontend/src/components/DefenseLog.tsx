import React, { useRef, useEffect, useState } from "react";
import type { AgentEvent, EventResult } from "./AttackTimeline";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

const severityConfig: Record<
  Severity,
  { color: string; bg: string; border: string }
> = {
  CRITICAL: {
    color: "#ef4444",
    bg: "rgba(239,68,68,0.18)",
    border: "rgba(239,68,68,0.5)",
  },
  HIGH: {
    color: "#f97316",
    bg: "rgba(249,115,22,0.15)",
    border: "rgba(249,115,22,0.5)",
  },
  MEDIUM: {
    color: "#eab308",
    bg: "rgba(234,179,8,0.12)",
    border: "rgba(234,179,8,0.4)",
  },
  LOW: {
    color: "#3b82f6",
    bg: "rgba(59,130,246,0.12)",
    border: "rgba(59,130,246,0.4)",
  },
};

const blueResultConfig: Record<
  EventResult,
  { label: string; color: string; bg: string }
> = {
  success: {
    label: "DEFENDED",
    color: "#22c55e",
    bg: "rgba(34,197,94,0.2)",
  },
  partial: {
    label: "PARTIAL",
    color: "#eab308",
    bg: "rgba(234,179,8,0.2)",
  },
  blocked: {
    label: "BLOCKED",
    color: "#3b82f6",
    bg: "rgba(59,130,246,0.2)",
  },
  detected: {
    label: "DETECTED",
    color: "#06b6d4",
    bg: "rgba(6,182,212,0.2)",
  },
  failed: {
    label: "FAILED",
    color: "#4b5563",
    bg: "rgba(75,85,99,0.2)",
  },
};

function getSeverity(event: AgentEvent): Severity {
  if (event.result === "failed") return "LOW";
  if (event.result === "success") return "CRITICAL";
  if (event.result === "detected") return "HIGH";
  if (event.result === "partial") return "MEDIUM";
  return "LOW";
}

const DefenseEntry: React.FC<{ event: AgentEvent; isNew: boolean }> = ({
  event,
  isNew,
}) => {
  const [expanded, setExpanded] = useState(false);
  const severity = getSeverity(event);
  const sev = severityConfig[severity];
  const res = blueResultConfig[event.result];
  const ts = new Date(event.timestamp);
  const timeStr = ts.toLocaleTimeString("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

  // Map blue event types to icons
  const icon = (() => {
    const s = event.summary.toLowerCase();
    if (s.includes("isolat")) return "🔒";
    if (s.includes("patch")) return "🔧";
    if (s.includes("alert") || s.includes("detect")) return "🔔";
    if (s.includes("block") || s.includes("rule")) return "🛡";
    if (s.includes("scan")) return "🔍";
    if (s.includes("firewall")) return "🧱";
    return "⚡";
  })();

  return (
    <div
      className="rounded-lg p-3 mb-2 cursor-pointer transition-all"
      style={{
        background: isNew ? "rgba(59,130,246,0.07)" : "rgba(255,255,255,0.02)",
        border: `1px solid ${isNew ? "rgba(59,130,246,0.35)" : "#1e2a45"}`,
        boxShadow: isNew ? "0 0 12px rgba(59,130,246,0.15)" : "none",
        animation: isNew ? "slideInBlue 0.3s ease-out" : "none",
      }}
      onClick={() => setExpanded((v) => !v)}
    >
      {/* Top row */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-base">{icon}</span>

        {/* Agent badge */}
        <span
          className="px-2 py-0.5 rounded text-[10px] font-bold font-mono"
          style={{
            background: "rgba(59,130,246,0.18)",
            border: "1px solid rgba(59,130,246,0.5)",
            color: "#93c5fd",
          }}
        >
          {event.agentName}
        </span>

        {/* Severity */}
        <span
          className="px-2 py-0.5 rounded text-[10px] font-bold tracking-wider"
          style={{
            background: sev.bg,
            border: `1px solid ${sev.border}`,
            color: sev.color,
          }}
        >
          {severity}
        </span>

        {/* Target */}
        {event.target && (
          <span className="text-[10px] font-mono text-cyan-300">
            ↳ {event.target}
          </span>
        )}

        {/* Result */}
        <span
          className="px-2 py-0.5 rounded text-[10px] font-bold tracking-wider ml-auto"
          style={{
            background: res.bg,
            border: `1px solid ${res.color}`,
            color: res.color,
          }}
        >
          {res.label}
        </span>
      </div>

      {/* MITRE technique reference */}
      {event.technique && (
        <p className="text-[10px] text-gray-500 mt-1 font-mono">
          Countering {event.technique}{" "}
          {event.techniqueName ? `— ${event.techniqueName}` : ""}
        </p>
      )}

      {/* Summary */}
      <p className="text-xs text-gray-300 mt-1.5 leading-relaxed">
        {event.summary}
      </p>

      {/* Expanded reasoning */}
      {expanded && event.reasoning && (
        <div
          className="mt-2 p-2 rounded text-[10px] font-mono text-gray-400 leading-relaxed"
          style={{
            background: "rgba(0,0,0,0.3)",
            border: "1px solid #1e2a45",
            whiteSpace: "pre-wrap",
          }}
        >
          <span className="text-blue-400 font-bold">ANALYSIS: </span>
          {event.reasoning}
        </div>
      )}

      {/* Timestamp */}
      <div className="flex justify-between items-center mt-2">
        <span className="text-[9px] text-gray-600 font-mono">{timeStr}</span>
        {event.reasoning && (
          <span className="text-[9px] text-gray-600">
            {expanded ? "▲ hide" : "▼ analysis"}
          </span>
        )}
      </div>
    </div>
  );
};

interface DefenseLogProps {
  events: AgentEvent[]; // pre-filtered to team === "blue"
  isActive: boolean;
}

export const DefenseLog: React.FC<DefenseLogProps> = ({ events, isActive }) => {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [newIds, setNewIds] = useState<Set<string>>(new Set());
  const prevCountRef = useRef(0);

  useEffect(() => {
    if (events.length > prevCountRef.current) {
      const freshIds = events
        .slice(0, events.length - prevCountRef.current)
        .map((e) => e.id);
      setNewIds(new Set(freshIds));
      const timer = setTimeout(() => setNewIds(new Set()), 2000);
      prevCountRef.current = events.length;
      return () => clearTimeout(timer);
    }
    prevCountRef.current = events.length;
  }, [events]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = 0;
    }
  }, [events.length]);

  return (
    <div
      className="flex flex-col h-full"
      style={{
        background: "#0b0f1c",
        border: "1px solid rgba(59,130,246,0.2)",
        borderRadius: 12,
        boxShadow: "0 0 20px rgba(59,130,246,0.05) inset",
      }}
    >
      {/* Header */}
      <div
        className="flex items-center gap-2 px-4 py-3 shrink-0"
        style={{ borderBottom: "1px solid rgba(59,130,246,0.15)" }}
      >
        <span
          className="text-base"
          style={{
            animation: isActive ? "shieldPulse 2s ease-in-out infinite" : "none",
            filter: isActive
              ? "drop-shadow(0 0 6px rgba(59,130,246,0.9))"
              : "none",
          }}
        >
          🛡
        </span>
        <h2
          className="text-xs font-bold tracking-widest uppercase"
          style={{ color: "#3b82f6", fontFamily: "monospace" }}
        >
          Blue Team Defense
        </h2>
        <span
          className="ml-auto text-[10px] font-mono px-2 py-0.5 rounded"
          style={{
            background: "rgba(59,130,246,0.1)",
            border: "1px solid rgba(59,130,246,0.2)",
            color: "#60a5fa",
          }}
        >
          {events.length} responses
        </span>
      </div>

      {/* Events list */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto p-3">
        {events.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-3 opacity-40">
            <span className="text-4xl">🛡</span>
            <p
              className="text-xs text-gray-500 text-center font-mono"
              style={{ letterSpacing: "0.1em" }}
            >
              Defense systems
              <br />
              standing by...
            </p>
          </div>
        ) : (
          events.map((event) => (
            <DefenseEntry
              key={event.id}
              event={event}
              isNew={newIds.has(event.id)}
            />
          ))
        )}
      </div>

      <style>{`
        @keyframes slideInBlue {
          from { opacity: 0; transform: translateY(-8px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @keyframes shieldPulse {
          0%, 100% { transform: scale(1); }
          50% { transform: scale(1.15); }
        }
      `}</style>
    </div>
  );
};

export default DefenseLog;
