import React, { useRef, useEffect, useState } from "react";

export type EventResult =
  | "success"
  | "partial"
  | "blocked"
  | "detected"
  | "failed";

export interface AgentEvent {
  id: string;
  team: "red" | "blue";
  timestamp: string; // ISO string
  agentName: string;
  technique?: string; // MITRE ID e.g. T1046
  techniqueName?: string;
  target?: string;
  result: EventResult;
  summary: string;
  reasoning?: string;
  confidence?: number;
  nextIntent?: string;
}

interface AttackTimelineProps {
  events: AgentEvent[]; // pre-filtered to team === "red"
  isActive: boolean;
}

const resultConfig: Record<
  EventResult,
  { label: string; color: string; bg: string }
> = {
  success: {
    label: "PWNED",
    color: "#ef4444",
    bg: "rgba(239,68,68,0.2)",
  },
  partial: {
    label: "PARTIAL",
    color: "#eab308",
    bg: "rgba(234,179,8,0.2)",
  },
  blocked: {
    label: "BLOCKED",
    color: "#6b7280",
    bg: "rgba(107,114,128,0.2)",
  },
  detected: {
    label: "DETECTED",
    color: "#f97316",
    bg: "rgba(249,115,22,0.2)",
  },
  failed: {
    label: "FAILED",
    color: "#4b5563",
    bg: "rgba(75,85,99,0.2)",
  },
};

const EventEntry: React.FC<{ event: AgentEvent; isNew: boolean }> = ({
  event,
  isNew,
}) => {
  const [expanded, setExpanded] = useState(false);
  const res = resultConfig[event.result];
  const ts = new Date(event.timestamp);
  const timeStr = ts.toLocaleTimeString("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

  return (
    <div
      className="rounded-lg p-3 mb-2 cursor-pointer transition-all"
      style={{
        background: isNew
          ? "rgba(239,68,68,0.07)"
          : "rgba(255,255,255,0.02)",
        border: `1px solid ${isNew ? "rgba(239,68,68,0.35)" : "#1e2a45"}`,
        boxShadow: isNew ? "0 0 12px rgba(239,68,68,0.15)" : "none",
        animation: isNew ? "slideIn 0.3s ease-out" : "none",
        transition: "all 0.3s ease",
      }}
      onClick={() => setExpanded((v) => !v)}
    >
      {/* Top row */}
      <div className="flex items-center justify-between gap-2 flex-wrap">
        {/* Agent badge */}
        <span
          className="px-2 py-0.5 rounded text-[10px] font-bold font-mono"
          style={{
            background: "rgba(239,68,68,0.18)",
            border: "1px solid rgba(239,68,68,0.5)",
            color: "#fca5a5",
          }}
        >
          {event.agentName}
        </span>

        {/* MITRE tag */}
        {event.technique && (
          <span
            className="px-2 py-0.5 rounded text-[10px] font-mono font-bold"
            style={{
              background: "rgba(168,85,247,0.15)",
              border: "1px solid rgba(168,85,247,0.4)",
              color: "#d8b4fe",
            }}
          >
            {event.technique}
          </span>
        )}

        {/* Target */}
        {event.target && (
          <span className="text-[10px] font-mono text-yellow-300">
            → {event.target}
          </span>
        )}

        {/* Result badge */}
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

      {/* Technique name */}
      {event.techniqueName && (
        <p className="text-[10px] text-gray-500 mt-1 font-mono">
          {event.techniqueName}
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
          <span className="text-red-500 font-bold">REASONING: </span>
          {event.reasoning}
        </div>
      )}

      {/* Timestamp + expand hint */}
      <div className="flex justify-between items-center mt-2">
        <span className="text-[9px] text-gray-600 font-mono">{timeStr}</span>
        {event.reasoning && (
          <span className="text-[9px] text-gray-600">
            {expanded ? "▲ hide" : "▼ reasoning"}
          </span>
        )}
      </div>
    </div>
  );
};

export const AttackTimeline: React.FC<AttackTimelineProps> = ({
  events,
  isActive,
}) => {
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

  // auto-scroll to top when new events arrive
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
        border: "1px solid rgba(239,68,68,0.2)",
        borderRadius: 12,
        boxShadow: "0 0 20px rgba(239,68,68,0.05) inset",
      }}
    >
      {/* Header */}
      <div
        className="flex items-center gap-2 px-4 py-3 shrink-0"
        style={{ borderBottom: "1px solid rgba(239,68,68,0.15)" }}
      >
        {isActive ? (
          <span
            className="w-2 h-2 rounded-full bg-red-500"
            style={{ animation: "blink 0.8s step-end infinite" }}
          />
        ) : (
          <span className="w-2 h-2 rounded-full bg-gray-600" />
        )}
        <h2
          className="text-xs font-bold tracking-widest uppercase"
          style={{ color: "#ef4444", fontFamily: "monospace" }}
        >
          Red Team Operations
        </h2>
        <span
          className="ml-auto text-[10px] font-mono px-2 py-0.5 rounded"
          style={{
            background: "rgba(239,68,68,0.1)",
            border: "1px solid rgba(239,68,68,0.2)",
            color: "#f87171",
          }}
        >
          {events.length} actions
        </span>
      </div>

      {/* Events list */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto p-3">
        {events.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-3 opacity-40">
            <span className="text-4xl">💀</span>
            <p
              className="text-xs text-gray-500 text-center font-mono"
              style={{ letterSpacing: "0.1em" }}
            >
              Awaiting red team
              <br />
              deployment...
            </p>
          </div>
        ) : (
          events.map((event) => (
            <EventEntry
              key={event.id}
              event={event}
              isNew={newIds.has(event.id)}
            />
          ))
        )}
      </div>

      <style>{`
        @keyframes slideIn {
          from { opacity: 0; transform: translateY(-8px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @keyframes blink {
          0%, 100% { opacity: 1; }
          50% { opacity: 0; }
        }
      `}</style>
    </div>
  );
};

export default AttackTimeline;
