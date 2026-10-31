import { useEffect, useRef, useState } from "react";
import { FiKey, FiMessageSquare, FiSend, FiTerminal } from "react-icons/fi";
import {
  askCopilot,
  ChatHistoryTurn,
  CopilotError,
  getStoredGeminiKey,
  setStoredGeminiKey,
} from "../services/copilotApi";
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
}

const QUICK_PROMPTS: Array<{ label: string; query: string; danger?: boolean }> =
  [
    {
      label: "Network Overview & Posture",
      query: "Tell me about the network and its security posture",
    },
    {
      label: "Live Sitrep & Why Approval Needed?",
      query:
        "What is happening right now and why does the Blue Agent wait for human approval?",
    },
    {
      label: "Reachability: Classified SQL DB",
      query: "Which devices can reach the classified SQL database?",
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

export function SOCCopilotChat({ simulationData }: SOCCopilotChatProps) {
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
    if (!question || loading) return;

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
      const res = await askCopilot(question, simulationData, history);
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
        <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
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
          {QUICK_PROMPTS.map((item) => (
            <button
              key={item.label}
              type="button"
              className={`copilot-chip ${
                item.danger ? "copilot-chip-danger" : ""
              }`}
              disabled={loading}
              onClick={() => void submitQuestion(item.query)}
            >
              {item.label}
            </button>
          ))}
        </div>
      </div>

      <div ref={listRef} className="copilot-messages">
        {messages.length === 0 && (
          <p className="copilot-placeholder">
            Ask anything about the loaded network, devices, attack paths, or
            Project Chronos (e.g., &ldquo;Tell me about the network&rdquo;,
            &ldquo;How are you?&rdquo;, or &ldquo;Which devices can reach the
            classified SQL database?&rdquo;).
          </p>
        )}

        {messages.map((m, i) => (
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
                <details style={{ marginTop: 6, fontSize: "0.74rem", opacity: 0.85 }}>
                  <summary style={{ cursor: "pointer", color: "#38bdf8" }}>
                    View context Cypher query
                  </summary>
                  <pre className="copilot-cypher">{m.cypher}</pre>
                </details>
              ) : (
                <pre className="copilot-cypher">{m.cypher}</pre>
              ))}
          </div>
        ))}
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
          placeholder="Ask about the network, devices, CVEs, or Project Chronos..."
          disabled={loading}
        />
        <button
          type="button"
          className="button button-primary"
          onClick={() => void handleSend()}
          disabled={loading || !input.trim()}
        >
          <FiSend />
          Send
        </button>
      </div>
    </section>
  );
}
