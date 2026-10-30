import { fetchTopology, useMockData } from "./api";

const BASE_URL = (
  import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000"
).replace(/\/$/, "");

export class CopilotError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export interface CopilotAnswer {
  cypher_query: string;
  raw_result: unknown[];
  answer: string;
}

const DESTRUCTIVE_RE =
  /\b(delete|remove|drop|destroy|wipe|sever|disconnect|cut|erase|truncate|create|insert|merge|update|modify|rename|overwrite)\b/i;

async function mockAskCopilot(question: string): Promise<CopilotAnswer> {
  const q = question.trim();
  if (!q) {
    throw new CopilotError(400, "Question must not be empty.");
  }
  if (DESTRUCTIVE_RE.test(q)) {
    throw new CopilotError(
      422,
      "Generated query contained a disallowed keyword."
    );
  }

  const topo = await fetchTopology();
  const ql = q.toLowerCase();

  if (/cve|vulnerab|exploit|unpatched/.test(ql)) {
    const withCves = topo.devices.filter((d) => d.cves && d.cves.length > 0);
    return {
      cypher_query:
        "MATCH (d:Device) WHERE size(d.cves) > 0 RETURN d.id AS id, d.name AS name, d.cves AS cves\nLIMIT 50",
      raw_result: withCves.map((d) => ({
        id: d.id,
        name: d.name,
        cves: d.cves,
      })),
      answer:
        withCves.length > 0
          ? `${withCves.length} device(s) have known CVEs: ${withCves
            .map((d) => `${d.id} (${d.cves.join(", ")})`)
            .join(", ")}.`
          : "No devices in the current topology have recorded CVEs.",
    };
  }

  if (/internal|core|secure|restricted/.test(ql)) {
    const internal = topo.devices.filter((d) => d.subnet === "internal_core");
    return {
      cypher_query:
        "MATCH (d:Device)-[:PART_OF_SUBNET]->(s:Subnet {id: 'internal_core'}) RETURN d.id AS id, d.name AS name, d.ip AS ip\nLIMIT 50",
      raw_result: internal.map((d) => ({ id: d.id, name: d.name, ip: d.ip })),
      answer: `Found ${internal.length} device(s) in internal_core: ${internal
        .map((d) => `${d.id} (${d.ip})`)
        .join(", ")}.`,
    };
  }

  if (/public|dmz|external|internet/.test(ql)) {
    const pub = topo.devices.filter((d) => d.subnet === "public_dmz");
    return {
      cypher_query:
        "MATCH (d:Device)-[:PART_OF_SUBNET]->(s:Subnet {id: 'public_dmz'}) RETURN d.id AS id, d.name AS name, d.ip AS ip\nLIMIT 50",
      raw_result: pub.map((d) => ({ id: d.id, name: d.name, ip: d.ip })),
      answer: `Found ${pub.length} device(s) in public_dmz: ${pub
        .map((d) => `${d.id} (${d.ip})`)
        .join(", ")}.`,
    };
  }

  if (/connect|link|route|edge|path|talk|reach|neighbo/.test(ql)) {
    return {
      cypher_query:
        "MATCH (a:Device)-[r:CONNECTS_TO]->(b:Device) RETURN a.id AS source, b.id AS target, r.type AS type\nLIMIT 50",
      raw_result: topo.connections,
      answer: `Found ${topo.connections.length} active connection(s): ${topo.connections
        .map((c) => `${c.source} -> ${c.target}`)
        .join(", ")}.`,
    };
  }

  if (/device|server|host|node|asset|all|list|show|how many|count/.test(ql)) {
    return {
      cypher_query:
        "MATCH (d:Device) RETURN d.id AS id, d.name AS name, d.ip AS ip, d.os AS os\nLIMIT 50",
      raw_result: topo.devices.map((d) => ({
        id: d.id,
        name: d.name,
        ip: d.ip,
        os: d.os,
      })),
      answer: `Found ${topo.devices.length} device(s) in the topology: ${topo.devices
        .map((d) => `${d.name} (${d.id})`)
        .join(", ")}.`,
    };
  }

  throw new CopilotError(
    422,
    "Offline copilot could not understand that question."
  );
}

export async function askCopilot(question: string): Promise<CopilotAnswer> {
  if (useMockData) {
    return mockAskCopilot(question);
  }
  const response = await fetch(`${BASE_URL}/copilot/ask`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ question }),
  });
  if (!response.ok) {
    throw new CopilotError(
      response.status,
      `Request failed with status ${response.status}`
    );
  }
  return response.json();
}
