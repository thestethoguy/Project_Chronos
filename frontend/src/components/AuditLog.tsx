import { useEffect, useRef } from "react";
import type { AuditLog as AuditLogItem } from "../types/simulation";

interface AuditLogProps {
  logs: AuditLogItem[];
}

export function AuditLog({ logs }: AuditLogProps) {
  const logEndRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  return (
    <section className="panel side-panel-section log-panel">
      <div className="panel-heading compact">
        <div>
          <p className="eyebrow">REAL-TIME STREAM</p>
          <h2>Audit Logs</h2>
        </div>
      </div>

      <div className="log-list">
        {logs.map((log) => (
          <article className={`log-entry log-${log.type}`} key={log.id}>
            <div>
              <span className="log-type">{log.type.toUpperCase()}</span>
              <time>{log.timestamp}</time>
            </div>
            <p>{log.message}</p>
          </article>
        ))}
        <div ref={logEndRef} />
      </div>
    </section>
  );
}
