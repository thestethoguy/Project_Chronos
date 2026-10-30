import { useEffect, useRef } from "react";
import type { AuditLog as AuditLogItem } from "../types/simulation";

interface AuditLogProps {
  logs: AuditLogItem[];
}

export function AuditLog({ logs }: AuditLogProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const prevLenRef = useRef<number>(logs.length);
  const prevLastIdRef = useRef<string | undefined>(
    logs[logs.length - 1]?.id
  );

  useEffect(() => {
    const lastId = logs[logs.length - 1]?.id;
    const hasNewEntry =
      logs.length > prevLenRef.current ||
      lastId !== prevLastIdRef.current;

    prevLenRef.current = logs.length;
    prevLastIdRef.current = lastId;

    // Scroll ONLY the inner overflow container; never call scrollIntoView() on window!
    if (hasNewEntry && containerRef.current) {
      containerRef.current.scrollTop =
        containerRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <section className="panel side-panel-section log-panel">
      <div className="panel-heading compact">
        <div>
          <p className="eyebrow">REAL-TIME STREAM</p>
          <h2>Audit Logs</h2>
        </div>
      </div>

      <div ref={containerRef} className="log-list audit-log-list">
        {logs.map((log) => (
          <article className={`log-entry log-${log.type}`} key={log.id}>
            <div>
              <span className="log-type">{log.type.toUpperCase()}</span>
              <time>{log.timestamp}</time>
            </div>
            <p>{log.message}</p>
          </article>
        ))}
      </div>
    </section>
  );
}
