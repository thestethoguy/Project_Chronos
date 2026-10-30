import { useState } from "react";
import { FiMessageSquare, FiSend } from "react-icons/fi";
import { askCopilot, CopilotError } from "../services/copilotApi";

type Message =
  | { role: "user"; text: string }
  | { role: "copilot"; text: string; cypher: string }
  | { role: "error"; text: string };

export function SOCCopilotChat() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSend() {
    const question = input.trim();
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
          ? "That question could not be safely translated into a query — try rephrasing it."
          : "The Copilot could not answer right now. Please try again.";
      setMessages((m) => [...m, { role: "error", text }]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="panel side-panel-section copilot-panel">
      <div className="panel-heading compact">
        <div>
          <p className="eyebrow">GRAPH QUERY ASSISTANT</p>
          <h2>
            <FiMessageSquare style={{ marginRight: 8, verticalAlign: "middle" }} />
            SOC Copilot
          </h2>
        </div>
      </div>

      <div className="copilot-messages">
        {messages.length === 0 && (
          <p className="copilot-placeholder">
            Ask read-only topology questions (e.g., &ldquo;Which devices are in
            the internal subnet?&rdquo; or &ldquo;Which devices have known
            CVEs?&rdquo;).
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
                  ? "Analyst"
                  : m.role === "copilot"
                  ? "SOC Copilot"
                  : "Validation Notice"}
              </strong>
            </div>
            <p>{m.text}</p>
            {m.role === "copilot" && (
              <pre className="copilot-cypher">{m.cypher}</pre>
            )}
          </div>
        ))}
        {loading && <p className="copilot-thinking">Translating &amp; querying graph...</p>}
      </div>

      <div className="copilot-input-row">
        <input
          className="copilot-input"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleSend()}
          placeholder="Ask about devices, subnets, CVEs, or routes..."
          disabled={loading}
        />
        <button
          type="button"
          className="button button-primary"
          onClick={handleSend}
          disabled={loading || !input.trim()}
        >
          <FiSend />
          Send
        </button>
      </div>
    </section>
  );
}

