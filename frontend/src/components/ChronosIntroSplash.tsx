import { useEffect, useState } from "react";
import { ChronosEmblem } from "./ChronosEmblem";

interface ChronosIntroSplashProps {
  visible: boolean;
  onComplete: () => void;
}

const BOOT_TELEMETRY_LINES = [
  {
    label: "NEO4J GRAPH TOPOLOGY SUBSTRATE",
    status: "[ONLINE]",
    color: "#38bdf8",
  },
  {
    label: "ISOLATION FOREST ML ANOMALY ENGINE",
    status: "[CALIBRATED]",
    color: "#60a5fa",
  },
  {
    label: "768-DIM VECTOR RAG INCIDENT MEMORY",
    status: "[16 LOGS ARMED]",
    color: "#2dd4bf",
  },
  {
    label: "RED APT vs. BLUE SOAR + HITL GATEWAY",
    status: "[BOUNDED & READY]",
    color: "#4ade80",
  },
];

export function ChronosIntroSplash({
  visible,
  onComplete,
}: ChronosIntroSplashProps) {
  const [exiting, setExiting] = useState(false);

  useEffect(() => {
    if (!visible) {
      setExiting(false);
      return;
    }
    setExiting(false);
    const fadeTimer = window.setTimeout(() => {
      setExiting(true);
    }, 2050);
    const doneTimer = window.setTimeout(() => {
      onComplete();
    }, 2500);

    return () => {
      window.clearTimeout(fadeTimer);
      window.clearTimeout(doneTimer);
    };
  }, [visible, onComplete]);

  if (!visible) return null;

  return (
    <div
      className={`chronos-intro-overlay ${
        exiting ? "chronos-intro-exiting" : ""
      }`}
      role="dialog"
      aria-label="Project Chronos Holographic Initialization"
    >
      {/* Skip Button in Top Right */}
      <button
        type="button"
        className="chronos-intro-skip-btn"
        onClick={onComplete}
      >
        Skip Intro ⏭
      </button>

      {/* Holographic Grid & Vertical Scanline */}
      <div className="chronos-intro-grid-bg" />
      <div className="chronos-intro-scanline" />

      <div className="chronos-intro-centerpiece">
        {/* Holographic Emblem Projection Stage */}
        <div className="chronos-intro-emblem-stage">
          <div className="chronos-intro-halo-ring chronos-intro-halo-outer" />
          <div className="chronos-intro-halo-ring chronos-intro-halo-inner" />
          <ChronosEmblem size={142} animated={true} />
        </div>

        {/* Title & Subtitle */}
        <p className="chronos-intro-eyebrow">
          AUTONOMOUS CYBER-RESILIENCE DIGITAL TWIN // v2.0
        </p>
        <h1 className="chronos-intro-title">PROJECT CHRONOS</h1>
        <p className="chronos-intro-subtitle">
          Initializing Multi-Agent Purple-Team Telemetry &amp; Bounded SOAR
          Governance
        </p>

        {/* Staggered Telemetry Boot Readout Bars */}
        <div className="chronos-intro-telemetry-box">
          {BOOT_TELEMETRY_LINES.map((item, idx) => (
            <div
              key={item.label}
              className="chronos-intro-telemetry-row"
              style={{ animationDelay: `${idx * 0.24}s` }}
            >
              <span className="chronos-intro-telemetry-label">
                {item.label}
              </span>
              <span className="chronos-intro-telemetry-dots" />
              <strong
                className="chronos-intro-telemetry-status"
                style={{ color: item.color }}
              >
                {item.status}
              </strong>
            </div>
          ))}
        </div>

        {/* Progress Bar */}
        <div className="chronos-intro-progress-track">
          <div className="chronos-intro-progress-fill" />
        </div>
      </div>
    </div>
  );
}
