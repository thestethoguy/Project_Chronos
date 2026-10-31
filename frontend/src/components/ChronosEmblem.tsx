import { useId } from "react";

interface ChronosEmblemProps {
  size?: number;
  animated?: boolean;
  variant?: "full" | "hologram";
  className?: string;
}

export function ChronosEmblem({
  size = 54,
  animated = true,
  variant = "full",
  className = "",
}: ChronosEmblemProps) {
  const uid = useId().replace(/:/g, "");
  const isHolo = variant === "hologram";

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 120 120"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={`chronos-emblem-svg ${
        animated ? "chronos-emblem-animated" : ""
      } ${isHolo ? "chronos-emblem-hologram" : ""} ${className}`}
      aria-hidden="true"
    >
      <defs>
        <radialGradient id={`bg-${uid}`} cx="50%" cy="50%" r="55%">
          <stop
            offset="0%"
            stopColor={isHolo ? "#0c2d48" : "#0f2947"}
            stopOpacity={isHolo ? "0.55" : "0.96"}
          />
          <stop
            offset="100%"
            stopColor="#040b14"
            stopOpacity={isHolo ? "0.25" : "0.98"}
          />
        </radialGradient>

        <linearGradient
          id={`shield-${uid}`}
          x1="18"
          y1="14"
          x2="102"
          y2="106"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0%" stopColor="#38bdf8" />
          <stop offset="52%" stopColor="#2563eb" />
          <stop offset="100%" stopColor="#f43f5e" />
        </linearGradient>

        <linearGradient
          id={`shieldFill-${uid}`}
          x1="30"
          y1="20"
          x2="90"
          y2="100"
          gradientUnits="userSpaceOnUse"
        >
          <stop
            offset="0%"
            stopColor="#0ea5e9"
            stopOpacity={isHolo ? "0.18" : "0.28"}
          />
          <stop
            offset="65%"
            stopColor="#0f172a"
            stopOpacity={isHolo ? "0.25" : "0.75"}
          />
          <stop
            offset="100%"
            stopColor="#f43f5e"
            stopOpacity={isHolo ? "0.14" : "0.24"}
          />
        </linearGradient>

        <filter id={`glow-${uid}`} x="-25%" y="-25%" width="150%" height="150%">
          <feGaussianBlur stdDeviation="2.4" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      {/* Deep Cyber Core Backdrop */}
      <circle
        cx="60"
        cy="60"
        r="55"
        fill={`url(#bg-${uid})`}
        stroke="#1e3a5f"
        strokeWidth="1.2"
      />

      {/* Outer Chronos Temporal Dial Ring (Rotating) */}
      <g className="chronos-ring-outer">
        <circle
          cx="60"
          cy="60"
          r="51"
          stroke="#38bdf8"
          strokeOpacity={isHolo ? "0.45" : "0.55"}
          strokeWidth="1.2"
          strokeDasharray="6 4 2 4"
        />
        {/* 12 Temporal Clockwork Notches */}
        <line x1="60" y1="6" x2="60" y2="12" stroke="#38bdf8" strokeWidth="1.8" />
        <line x1="60" y1="108" x2="60" y2="114" stroke="#f43f5e" strokeWidth="1.8" />
        <line x1="6" y1="60" x2="12" y2="60" stroke="#38bdf8" strokeWidth="1.8" />
        <line x1="108" y1="60" x2="114" y2="60" stroke="#f43f5e" strokeWidth="1.8" />
        <line x1="22" y1="22" x2="26" y2="26" stroke="#38bdf8" strokeWidth="1.3" />
        <line x1="98" y1="22" x2="94" y2="26" stroke="#38bdf8" strokeWidth="1.3" />
        <line x1="22" y1="98" x2="26" y2="94" stroke="#f43f5e" strokeWidth="1.3" />
        <line x1="98" y1="98" x2="94" y2="94" stroke="#f43f5e" strokeWidth="1.3" />
      </g>

      {/* Dual Agent Counter-Rotating Orbital Arcs (Blue SOAR vs Red APT) */}
      <g className="chronos-ring-inner">
        <path
          d="M 16 60 A 44 44 0 0 1 60 16"
          stroke="#38bdf8"
          strokeWidth="2.2"
          strokeLinecap="round"
        />
        <path
          d="M 104 60 A 44 44 0 0 1 60 104"
          stroke="#f43f5e"
          strokeWidth="2.2"
          strokeLinecap="round"
        />
      </g>

      {/* Hexagonal Cyber-Resilience Shield */}
      <polygon
        points="60,17 96,36 96,77 60,103 24,77 24,36"
        fill={`url(#shieldFill-${uid})`}
        stroke={`url(#shield-${uid})`}
        strokeWidth="2.4"
        strokeLinejoin="round"
        filter={`url(#glow-${uid})`}
      />

      {/* Inner Shield Etched Frame */}
      <polygon
        points="60,24 89,40 89,73 60,95 31,73 31,40"
        fill="none"
        stroke="#60a5fa"
        strokeOpacity="0.32"
        strokeWidth="1"
        strokeDasharray="3 3"
      />

      {/* Neo4j 5-Node Digital Twin Graph Constellation + Temporal Hands */}
      <g strokeWidth="1.7" strokeLinecap="round">
        {/* Directed Graph Edges */}
        <line x1="41" y1="45" x2="60" y2="35" stroke="#38bdf8" strokeOpacity="0.85" />
        <line x1="60" y1="35" x2="79" y2="45" stroke="#38bdf8" strokeOpacity="0.85" />
        <line x1="41" y1="45" x2="60" y2="60" stroke="#38bdf8" strokeOpacity="0.95" />
        <line x1="79" y1="45" x2="60" y2="60" stroke="#60a5fa" strokeOpacity="0.95" />
        <line x1="60" y1="60" x2="45" y2="79" stroke="#38bdf8" strokeOpacity="0.9" />
        <line x1="60" y1="60" x2="75" y2="79" stroke="#f43f5e" strokeOpacity="0.95" />
        <line
          x1="45"
          y1="79"
          x2="75"
          y2="79"
          stroke="#f43f5e"
          strokeOpacity="0.75"
          strokeDasharray="2.5 2.5"
        />
      </g>

      {/* Outer Graph Constellation Nodes */}
      <circle cx="60" cy="35" r="3.6" fill="#38bdf8" stroke="#e0f2fe" strokeWidth="1.2" />
      <circle cx="41" cy="45" r="3.6" fill="#38bdf8" stroke="#e0f2fe" strokeWidth="1.2" />
      <circle cx="79" cy="45" r="3.6" fill="#60a5fa" stroke="#e0f2fe" strokeWidth="1.2" />
      <circle cx="45" cy="79" r="3.6" fill="#2dd4bf" stroke="#ccfbf1" strokeWidth="1.2" />
      <circle cx="75" cy="79" r="3.8" fill="#f43f5e" stroke="#ffe4e6" strokeWidth="1.2" />

      {/* Central Chronos Temporal Core Node */}
      <circle
        cx="60"
        cy="60"
        r="7.2"
        fill="#081a2e"
        stroke="#38bdf8"
        strokeWidth="2"
      />
      <circle
        cx="60"
        cy="60"
        r="3.4"
        fill="#7dd3fc"
        className="chronos-core-pulse"
      />
    </svg>
  );
}
