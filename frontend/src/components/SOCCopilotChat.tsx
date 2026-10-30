import { useEffect, useRef, useState } from "react";
import { FiMessageSquare, FiSend, FiTerminal } from "react-icons/fi";
import { askCopilot, CopilotError } from "../services/copilotApi";

type Message =
  | { role: "user"; text: string }
  | { role: "copilot"; text: string; cypher: string }
  | { role: "error"; text: string };

const QUICK_PROMPTS: Array<{ label: string; query: string; danger?: boolean }> =
  [
    {
      label: "Reachability: Classified SQL DB",
      query: "Which devices can reach the classified SQL database?",
    },
    {
      label: "Internal Core Subnet Assets",
      query: "List all devices in the internal core subnet",
    },
    {
      label: "Unpatched CVE Exposure",
      query: "Which devices have known CVEs?",
    },
    {
      label: "Test Guardrail: DELETE all connections (should block)",
      query: "DELETE all connections in the network",
      danger: true,
    },
  ];

export function SOCCopilotChat() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);

  const listRef = useRef<HTMLDivElement | null>(null);
  const prevLenRef = useRef<number>(0);

  useEffect(() => {
    if (messages.length > prevLenRef.current && listRef.current) {
      listRef.current.scrollTop = listRef.current.scrollHeight;
    }
    prevLenRef.current = messages.length;
  }, [messages]);

  async function submitQuestion(rawQuestion: string) {
    const question = rawQuestion.trim();
    if (!question || loading) return;
    setMessages((m) => [...m, { role: "user", text: question }]);
    setInput("");
    setLoading(true);
    try {
      const res = await askCopilot(question);
      setMessages((m) => [
        ...m,
        { role: "copilot", text: res.answer, cypher: res.cypher_query },
      ]);
    } catch (err) {
      const status = err instanceof CopilotError ? err.status : undefined;
      const text =
        status === 422
          ? "Guardrail Blocked (HTTP 422): That question could not be safely translated into a read-only Cypher query."
          : "The Copilot could not answer right now. Please try again.";
      setMessages((m) => [...m, { role: "error", text }]);
    } finally {
      setLoading(false);
    }
  }

  async function handleSend() {
    await submitQuestion(input);
  }

  return (
    <section className="panel side-panel-section copilot-panel">
      <div className="panel-heading compact">
        <div>
          <p className="eyebrow">NL-TO-CYPHER GRAPH ASSISTANT</p>
          <h2>
            <FiMessageSquare style={{ marginRight: 8, verticalAlign: "middle" }} />
            SOC Copilot
          </h2>
        </div>
        <span className="copilot-readonly-badge">READ-ONLY GUARD</span>
      </div>

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
            Click a quick query above or ask any read-only topology question
            (e.g., &ldquo;Which devices can reach the classified SQL
            database?&rdquo;).
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
            <p>{m.text}</p>
            {m.role === "copilot" && (
              <pre className="copilot-cypher">{m.cypher}</pre>
            )}
          </div>
        ))}
        {loading && (
          <p className="copilot-thinking">
            Translating NL ➔ Cypher &amp; querying topology...
          </p>
        )}
      </div>

      <div className="copilot-input-row">
        <input
          className="copilot-input"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && void handleSend()}
          placeholder="Ask about devices, subnets, CVEs, or routes..."
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
