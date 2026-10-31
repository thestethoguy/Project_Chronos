import { ChronosEmblem } from "./ChronosEmblem";

const CORNER_ITEMS: Array<{
  pos: "top-left" | "top-right" | "bottom-left" | "bottom-right";
  code: string;
  sub: string;
}> = [
  {
    pos: "top-left",
    code: "CHRONOS // DIGITAL-TWIN v2.0",
    sub: "HOLO-HUD · NODE-01",
  },
  {
    pos: "top-right",
    code: "RED-APT // BLUE-SOAR CORE",
    sub: "PURPLE-TEAM · SYNC",
  },
  {
    pos: "bottom-left",
    code: "NEO4J // RAG-768 GROUNDED",
    sub: "GRAPH-MEM · ACTIVE",
  },
  {
    pos: "bottom-right",
    code: "HITL-GATE // AWS-GUARD",
    sub: "BOUNDED-AUTH · LOCK",
  },
];

export function ChronosCornerHolograms() {
  return (
    <div className="chronos-corner-holograms-layer" aria-hidden="true">
      {CORNER_ITEMS.map((item) => (
        <div
          key={item.pos}
          className={`chronos-corner-holo chronos-corner-${item.pos}`}
        >
          <span className="chronos-holo-bracket" />
          <div className="chronos-holo-inner">
            <div className="chronos-holo-emblem-box">
              <ChronosEmblem
                size={34}
                animated={false}
                variant="hologram"
              />
            </div>
            <div className="chronos-holo-meta">
              <span className="chronos-holo-code">{item.code}</span>
              <span className="chronos-holo-sub">{item.sub}</span>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

