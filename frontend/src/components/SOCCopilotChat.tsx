import { useEffect, useMemo, useRef, useState } from "react";
import {
  FiFolderPlus,
  FiKey,
  FiLock,
  FiMessageSquare,
  FiSend,
  FiTerminal,
  FiZap,
} from "react-icons/fi";
import {
  askCopilot,
  ChatHistoryTurn,
  CopilotError,
  getStoredGeminiKey,
  setStoredGeminiKey,
} from "../services/copilotApi";
import type { TopologyEntryMode } from "./TopologyUploader";
import type { SimulationData } from "../types/simulation";

type Message =
  | { role: "user"; text: string }
  | {
      role: "copilot";
      text: string;
      cypher: string;
      conversational?: boolean;
      mode?: string;
    }
  | { role: "error"; text: string };

interface SOCCopilotChatProps {
  simulationData?: SimulationData;
  topologyMode?: TopologyEntryMode;
  topologySourceName?: string;
  topologyRefreshKey?: number;
  onLaunchDemo?: () => void;
  onScrollToUploader?: () => void;
}

export function SOCCopilotChat({
  simulationData,
  topologyMode,
  topologySourceName,
  topologyRefreshKey = 0,
  onLaunchDemo,
  onScrollToUploader,
}: SOCCopilotChatProps) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [showKeyConfig, setShowKeyConfig] = useState(false);
  const [geminiKey, setGeminiKey] = useState<string>(() =>
    getStoredGeminiKey()
  );
  const [keyDraft, setKeyDraft] = useState<string>(() => getStoredGeminiKey());
  const [activeEngine, setActiveEngine] = useState<string>(() =>
    getStoredGeminiKey() ? "gemini" : "chronos"
  );

  const listRef = useRef<HTMLDivElement | null>(null);
  const prevLenRef = useRef<number>(0);

  const effectiveMode: TopologyEntryMode =
    topologyMode ??
    (!simulationData ||
    simulationData.simulationId === "SIM-STANDBY" ||
    simulationData.nodes.length === 0
      ? "standby"
      : "demo");

  const nodes = useMemo(
    () => simulationData?.nodes ?? [],
    [simulationData?.nodes]
  );
  const edges = useMemo(
    () => simulationData?.edges ?? [],
    [simulationData?.edges]
  );

  const isStandby =
    effectiveMode === "standby" ||
    !simulationData ||
    simulationData.simulationId === "SIM-STANDBY" ||
    nodes.length === 0;

  // Signature of the active topology so any topology switch/upload resets chat from scratch
  const nodeIdsSignature = useMemo(
    () => nodes.map((n) => n.id).join(","),
    [nodes]
  );

  useEffect(() => {
    setInput("");
    setLoading(false);
    prevLenRef.current = 0;

    if (isStandby || nodes.length === 0) {
      setMessages([]);
      return;
    }

    const activeSource =
      topologySourceName ||
      (effectiveMode === "demo"
        ? "20-Node Enterprise Reference"
        : "Custom Uploaded Topology");
    const sampleNodes = nodes
      .slice(0, 3)
      .map((n) => `${n.label} (${n.id})`)
      .join(", ");
    const targetNode =
      nodes.filter((n) => n.subnet === "internal_core").slice(-1)[0] ??
      nodes[nodes.length - 1];
    const dmzCount = nodes.filter((n) => n.subnet === "public_dmz").length;
    const coreCount = nodes.filter((n) => n.subnet === "internal_core").length;

    setMessages([
      {
        role: "copilot",
        conversational: true,
        mode: getStoredGeminiKey() ? "gemini" : "offline",
        cypher:
          "MATCH (d:Device) RETURN d.id AS id, d.name AS name, d.ip AS ip, d.subnet AS subnet\nLIMIT 50",
        text:
          ` SOC Copilot session initialized for [${activeSource}] (${
            effectiveMode === "demo" ? "Demo Mode" : "Custom Blueprint Mode"
          }).\n` +
          `• Active Graph: ${nodes.length} devices (${dmzCount} public_dmz, ${coreCount} internal_core) and ${edges.length} connections.\n` +
          `• Sample Active Nodes: ${sampleNodes}.\n` +
          `Ask me anything about this topology — e.g., "Tell me about the network", "Which devices can reach ${
            targetNode?.id ?? nodes[0].id
          }?", or "Which node is most at risk and how do I harden it?"`,
      },
    ]);
  }, [
    effectiveMode,
    topologySourceName,
    topologyRefreshKey,
    isStandby,
    nodeIdsSignature,
    nodes,
    edges.length,
  ]);

  // Dynamic Quick-Query Chips derived from the actual loaded topology
  const dynamicQuickPrompts = useMemo(() => {
    const coreNodes = nodes.filter((n) => n.subnet === "internal_core");
    const dmzNodes = nodes.filter((n) => n.subnet === "public_dmz");
    const targetNode =
      coreNodes[coreNodes.length - 1] ?? nodes[nodes.length - 1];
    const entryNode = dmzNodes[0] ?? nodes[0];

    const reachLabel = targetNode
      ? `Reachability: ${targetNode.label || targetNode.id}`
      : "Reachability: Target Asset";
    const reachQuery = targetNode
      ? `Which devices can reach ${targetNode.id}?`
      : "Which devices can reach the core database?";

    const inspectLabel = entryNode
      ? `Inspect: ${entryNode.label || entryNode.id}`
      : "Inspect Perimeter Node";
    const inspectQuery = entryNode
      ? `Tell me about ${entryNode.id} and its connections`
      : "Tell me about the entry node";

    return [
      {
        label: "Network Overview & Posture",
        query: "Tell me about the network and its security posture",
      },
      {
        label: reachLabel,
        query: reachQuery,
      },
      {
        label: inspectLabel,
        query: inspectQuery,
      },
      {
        label: "Live Sitrep & Why Approval Needed?",
        query:
          "What is happening right now and why does the Blue Agent wait for human approval?",
      },
      {
        label: "Top Risk Node & How to Harden",
        query: "Which node is most at risk and how do I harden this network?",
      },
      {
        label: "Test Guardrail: DELETE all connections (should block)",
        query: "DELETE all connections in the network",
        danger: true,
      },
    ];
  }, [nodes]);

  useEffect(() => {
    if (messages.length > prevLenRef.current && listRef.current) {
      listRef.current.scrollTop = listRef.current.scrollHeight;
    }
    prevLenRef.current = messages.length;
  }, [messages]);

  function handleSaveKey() {
    const trimmed = keyDraft.trim();
    setStoredGeminiKey(trimmed);
    setGeminiKey(trimmed);
    setActiveEngine(trimmed ? "gemini" : "chronos");
    setShowKeyConfig(false);
  }

  function handleClearKey() {
    setStoredGeminiKey("");
    setGeminiKey("");
    setKeyDraft("");
    setActiveEngine("chronos");
    setShowKeyConfig(false);
  }

  async function submitQuestion(rawQuestion: string) {
    const question = rawQuestion.trim();
    if (!question || loading || isStandby) return;

    const history: ChatHistoryTurn[] = messages
      .filter(
        (m): m is Extract<Message, { role: "user" | "copilot" }> =>
          m.role === "user" || m.role === "copilot"
      )
      .slice(-6)
      .map((m) => ({ role: m.role, text: m.text }));

    setMessages((m) => [...m, { role: "user", text: question }]);
    setInput("");
    setLoading(true);
    try {
      const res = await askCopilot(
        question,
        simulationData,
        history,
        effectiveMode,
        topologySourceName
      );
      if (res.mode === "gemini" || res.mode === "groq") {
        setActiveEngine(res.mode);
      }
      setMessages((m) => [
        ...m,
        {
          role: "copilot",
          text: res.answer,
          cypher: res.cypher_query,
          conversational: res.conversational,
          mode: res.mode,
        },
      ]);
    } catch (err) {
      const status = err instanceof CopilotError ? err.status : undefined;
      const text =
        status === 422
          ? "Guardrail Blocked (HTTP 422): Destructive or write commands (DELETE, DROP, REMOVE, SET, CREATE) are strictly prohibited by the read-only Cypher validator."
          : "The Copilot could not answer right now. Please try again.";
      setMessages((m) => [...m, { role: "error", text }]);
    } finally {
      setLoading(false);
    }
  }

  async function handleSend() {
    await submitQuestion(input);
  }

  const isGeminiActive = Boolean(geminiKey) || activeEngine === "gemini";

  return (
    <section className="panel side-panel-section copilot-panel">
      <div className="panel-heading compact">
        <div>
          <p className="eyebrow">AI SOC SPECIALIST &amp; GRAPH ASSISTANT</p>
          <h2>
            <FiMessageSquare
              style={{ marginRight: 8, verticalAlign: "middle" }}
            />
            SOC Copilot
          </h2>
        </div>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 6,
            flexWrap: "wrap",
          }}
        >
          {isStandby ? (
            <span
              className="copilot-readonly-badge"
              style={{
                background: "rgba(245, 158, 11, 0.16)",
                border: "1px solid rgba(245, 158, 11, 0.5)",
                color: "#fbbf24",
              }}
              title="SOC Copilot is locked in Standby until you select Demo Mode or upload a Custom Topology (.json)"
            >
              🔒 STANDBY — SELECT TOPOLOGY
            </span>
          ) : (
            <span
              className="copilot-readonly-badge"
              title={
                isGeminiActive
                  ? "Powered by Live Google Gemini 2.5 Flash + Project Chronos Graph Context"
                  : "Powered by Project Chronos Conversational & Graph Intelligence Engine"
              }
            >
              {isGeminiActive ? "✨ GEMINI 2.5 FLASH" : "🧠 CHRONOS AI ENGINE"}
            </span>
          )}
          <button
            type="button"
            className="copilot-chip"
            onClick={() => setShowKeyConfig((v) => !v)}
            title="Configure optional Google Gemini API Key for live LLM responses in browser"
            style={{ padding: "3px 8px", fontSize: "0.72rem" }}
          >
            <FiKey style={{ marginRight: 4, verticalAlign: "middle" }} />
            {geminiKey ? "Key Active" : "API Key"}
          </button>
        </div>
      </div>

      {showKeyConfig && (
        <div
          style={{
            marginBottom: 10,
            padding: "8px 10px",
            borderRadius: 8,
            background: "rgba(15, 23, 42, 0.75)",
            border: "1px solid rgba(56, 189, 248, 0.3)",
            fontSize: "0.78rem",
          }}
        >
          <div style={{ marginBottom: 6, color: "#94a3b8" }}>
            Enter a Google Gemini API Key (saved locally in your browser&apos;s{" "}
            <code>localStorage</code>) to enable live{" "}
            <strong>gemini-2.5-flash</strong> responses on top of the built-in
            Chronos graph engine:
          </div>
          <div style={{ display: "flex", gap: 6 }}>
            <input
              type="password"
              className="copilot-input"
              value={keyDraft}
              onChange={(e) => setKeyDraft(e.target.value)}
              placeholder="Paste Gemini API key (AIza...)"
              style={{ flex: 1, padding: "5px 8px", fontSize: "0.78rem" }}
            />
            <button
              type="button"
              className="button button-primary"
              onClick={handleSaveKey}
              style={{ padding: "4px 10px", fontSize: "0.76rem" }}
            >
              Save
            </button>
            {geminiKey && (
              <button
                type="button"
                className="copilot-chip copilot-chip-danger"
                onClick={handleClearKey}
                style={{ padding: "4px 8px", fontSize: "0.76rem" }}
              >
                Clear
              </button>
            )}
          </div>
        </div>
      )}

      {/* 1-Click Analyst Quick-Query Chips */}
      <div className="copilot-quick-chips">
        <span className="copilot-chips-label">
          <FiTerminal /> Quick Queries:
        </span>
        <div className="copilot-chips-row">
          {dynamicQuickPrompts.map((item) => (
            <button
              key={item.label}
              type="button"
              className={`copilot-chip ${
                item.danger ? "copilot-chip-danger" : ""
              }`}
              disabled={loading || isStandby}
              title={
                isStandby
                  ? "Select Demo Mode or Upload Custom JSON first to unlock Quick Queries"
                  : item.query
              }
              onClick={() => void submitQuestion(item.query)}
            >
              {item.label}
            </button>
          ))}
        </div>
      </div>

      <div ref={listRef} className="copilot-messages">
        {isStandby ? (
          <div
            style={{
              padding: "16px",
              borderRadius: 10,
              background: "rgba(15, 23, 42, 0.85)",
              border: "1px dashed rgba(245, 158, 11, 0.45)",
              display: "flex",
              flexDirection: "column",
              gap: 10,
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                color: "#fbbf24",
                fontWeight: 700,
                fontSize: "0.86rem",
              }}
            >
              <FiLock />
              <span>SOC Copilot Locked — Awaiting Network Blueprint</span>
            </div>
            <p
              style={{
                margin: 0,
                fontSize: "0.8rem",
                color: "#cbd5e1",
                lineHeight: 1.48,
              }}
            >
              To guarantee zero sample-data bleed-over, the SOC Copilot remains
              on standby until you select a network topology. Choose the{" "}
              <strong>20-Node Enterprise Demo</strong> or upload your own{" "}
              <strong>Custom Topology (.json)</strong> to initialize a fresh,
              grounded chat session:
            </p>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              {onLaunchDemo && (
                <button
                  type="button"
                  className="button button-primary"
                  onClick={onLaunchDemo}
                  style={{
                    padding: "6px 12px",
                    fontSize: "0.78rem",
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 6,
                  }}
                >
                  <FiZap />
                  Load 20-Node Enterprise Demo
                </button>
              )}
              <button
                type="button"
                className="copilot-chip"
                onClick={() => {
                  onScrollToUploader?.();
                  const fileInput = document.getElementById(
                    "topology-file"
                  ) as HTMLInputElement | null;
                  fileInput?.focus();
                }}
                style={{
                  padding: "6px 12px",
                  fontSize: "0.78rem",
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 6,
                }}
              >
                <FiFolderPlus />
                Upload Custom Topology (.json)
              </button>
            </div>
          </div>
        ) : (
          messages.map((m, i) => (
            <div
              key={i}
              className={`copilot-message copilot-message-${m.role}`}
            >
              <div className="copilot-message-header">
                <strong>
                  {m.role === "user"
                    ? "SOC Analyst"
                    : m.role === "copilot"
                    ? "SOC Copilot"
                    : "Cypher Safety Validator"}
                </strong>
              </div>
              <p style={{ whiteSpace: "pre-line" }}>{m.text}</p>
              {m.role === "copilot" &&
                (m.conversational ? (
                  <details
                    style={{
                      marginTop: 6,
                      fontSize: "0.74rem",
                      opacity: 0.85,
                    }}
                  >
                    <summary style={{ cursor: "pointer", color: "#38bdf8" }}>
                      View context Cypher query
                    </summary>
                    <pre className="copilot-cypher">{m.cypher}</pre>
                  </details>
                ) : (
                  <pre className="copilot-cypher">{m.cypher}</pre>
                ))}
            </div>
          ))
        )}
        {loading && (
          <p className="copilot-thinking">
            Analyzing live topology &amp; generating SOC response...
          </p>
        )}
      </div>

      <div className="copilot-input-row">
        <input
          className="copilot-input"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && void handleSend()}
          placeholder={
            isStandby
              ? "🔒 Select Demo Mode or Upload Custom JSON first to unlock chat..."
              : "Ask about the network, devices, CVEs, or Project Chronos..."
          }
          disabled={loading || isStandby}
        />
        <button
          type="button"
          className="button button-primary"
          onClick={() => void handleSend()}
          disabled={loading || isStandby || !input.trim()}
        >
          <FiSend />
          Send
        </button>
      </div>
    </section>
  );
}
