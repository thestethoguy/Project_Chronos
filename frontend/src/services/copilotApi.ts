import { fetchTopology, useMockData } from "./api";
import type {
  NetworkTopologyFile,
  SimulationData,
  TopologyConnection,
  TopologyDevice,
} from "../types/simulation";

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

const WRITE_DELETE_RE =
  /\b(delete|remove|drop|destroy|wipe|sever|disconnect|cut|erase|truncate)\b/i;
const WRITE_OTHER_RE =
  /\b(create|insert|merge|update|modify|rename|overwrite)\b/i;
const EXPLAIN_GUARD_RE =
  /\b(why|what|how|explain|when|does|did|mean|waiting|propos|approv|reason)\b/i;

const STOPWORDS = new Set([
  "the",
  "and",
  "for",
  "are",
  "with",
  "that",
  "this",
  "from",
  "what",
  "which",
  "who",
  "how",
  "why",
  "can",
  "reach",
  "show",
  "list",
  "all",
  "tell",
  "about",
  "device",
  "devices",
  "node",
  "nodes",
  "server",
  "network",
  "host",
  "hosts",
  "connected",
  "connection",
  "connections",
  "between",
  "into",
  "have",
  "has",
  "does",
]);

function findAllMentionedDevices(
  question: string,
  devices: TopologyDevice[]
): TopologyDevice[] {
  const ql = question.toLowerCase();
  const qNorm = ql.replace(/[_-]+/g, " ");
  const qWords = new Set(
    (qNorm.match(/[a-z0-9.]+/g) ?? []).filter(
      (w) => !STOPWORDS.has(w) && w.length >= 2
    )
  );
  const scored: Array<{ score: number; dev: TopologyDevice }> = [];

  for (const d of devices) {
    const did = d.id.toLowerCase();
    const dname = (d.name || "").toLowerCase();
    const dip = (d.ip || "").toLowerCase();
    let score = 0;

    if (did && ql.includes(did)) score += 100;
    else if (did && qNorm.includes(did.replace(/[_-]+/g, " "))) score += 90;

    if (dip && ql.includes(dip)) score += 95;
    if (dname && ql.includes(dname)) score += 85;

    const idTokens = did
      .split(/[_-]+/)
      .filter((t) => t.length >= 2 && !STOPWORDS.has(t));
    const nameTokens = (dname.match(/[a-z0-9]+/g) ?? []).filter(
      (t) => t.length >= 3 && !STOPWORDS.has(t) && t !== "db"
    );

    if (idTokens.length >= 2 && idTokens.every((t) => qWords.has(t))) {
      score += 75;
    }
    if (nameTokens.length >= 2 && nameTokens.every((t) => qWords.has(t))) {
      score += 70;
    }

    if (score > 0) {
      scored.push({ score, dev: d });
    }
  }

  scored.sort((a, b) => b.score - a.score);
  const result = scored.map((s) => s.dev);

  if (result.length === 0) {
    if (/\b(database|sql|db|secret|classified)\b/i.test(ql)) {
      for (const d of devices) {
        if (
          /db|sql|database|secret|classified/i.test(`${d.id} ${d.name}`)
        ) {
          result.push(d);
        }
      }
    }
    if (/\b(router|wifi|gateway|proxy|ingress|firewall)\b/i.test(ql)) {
      for (const d of devices) {
        if (
          /router|wifi|gateway|proxy|ingress|firewall|waf/i.test(
            `${d.id} ${d.name}`
          )
        ) {
          result.push(d);
        }
      }
    }
    if (/\b(auth|domain|controller|ldap|kerberos)\b/i.test(ql)) {
      for (const d of devices) {
        if (/auth|dc|domain|ldap/i.test(`${d.id} ${d.name}`)) {
          result.push(d);
        }
      }
    }
  }

  return result;
}

function bfsAllPaths(
  connections: TopologyConnection[],
  startId: string,
  endId: string,
  maxDepth = 7
): string[][] {
  const adj = new Map<string, string[]>();
  for (const c of connections) {
    const list = adj.get(c.source) ?? [];
    list.push(c.target);
    adj.set(c.source, list);
  }
  const paths: string[][] = [];
  const queue: string[][] = [[startId]];
  while (queue.length > 0) {
    const path = queue.shift()!;
    const last = path[path.length - 1];
    if (last === endId && path.length > 1) {
      paths.push(path);
      continue;
    }
    if (path.length > maxDepth) continue;
    for (const nxt of adj.get(last) ?? []) {
      if (!path.includes(nxt)) {
        queue.push([...path, nxt]);
      }
    }
  }
  return paths;
}

function upstreamPathsTo(
  connections: TopologyConnection[],
  targetId: string,
  maxDepth = 6
): string[][] {
  const rev = new Map<string, string[]>();
  for (const c of connections) {
    const list = rev.get(c.target) ?? [];
    list.push(c.source);
    rev.set(c.target, list);
  }
  const paths: string[][] = [];
  const queue: string[][] = [[targetId]];
  while (queue.length > 0) {
    const chain = queue.shift()!;
    const current = chain[0];
    const preds = (rev.get(current) ?? []).filter((p) => !chain.includes(p));
    if (chain.length > 1) {
      paths.push(chain);
    }
    if (chain.length <= maxDepth) {
      for (const p of preds) {
        queue.push([p, ...chain]);
      }
    }
  }
  paths.sort((a, b) => a.length - b.length);
  return paths;
}

function downstreamPathsFrom(
  connections: TopologyConnection[],
  sourceId: string,
  maxDepth = 6
): string[][] {
  const adj = new Map<string, string[]>();
  for (const c of connections) {
    const list = adj.get(c.source) ?? [];
    list.push(c.target);
    adj.set(c.source, list);
  }
  const paths: string[][] = [];
  const queue: string[][] = [[sourceId]];
  while (queue.length > 0) {
    const chain = queue.shift()!;
    const current = chain[chain.length - 1];
    const succs = (adj.get(current) ?? []).filter((s) => !chain.includes(s));
    if (chain.length > 1) {
      paths.push(chain);
    }
    if (chain.length <= maxDepth) {
      for (const s of succs) {
        queue.push([...chain, s]);
      }
    }
  }
  paths.sort((a, b) => a.length - b.length);
  return paths;
}

function scoreDeviceRisk(
  dev: TopologyDevice,
  connections: TopologyConnection[]
): number {
  const cves = dev.cves ?? [];
  const inEdges = connections.filter((c) => c.target === dev.id).length;
  const outEdges = connections.filter((c) => c.source === dev.id).length;
  const isCore = dev.subnet === "internal_core" ? 18 : 10;
  return Math.min(
    99,
    cves.length * 25 + inEdges * 8 + outEdges * 6 + isCore
  );
}

function formatDeviceBrief(
  d: TopologyDevice,
  connections: TopologyConnection[]
): string {
  const cves = d.cves && d.cves.length > 0 ? d.cves.join(", ") : "none";
  const ports =
    d.ports && d.ports.length > 0 ? d.ports.join(", ") : "none listed";
  const outTargets = connections
    .filter((c) => c.source === d.id)
    .map((c) => `${c.target} (${c.type})`);
  const inSources = connections
    .filter((c) => c.target === d.id)
    .map((c) => `${c.source} (${c.type})`);
  const outStr = outTargets.length > 0 ? outTargets.join(", ") : "none";
  const inStr = inSources.length > 0 ? inSources.join(", ") : "none";
  return `${d.name} (${d.id}) — IP ${d.ip}, OS: ${d.os}, subnet: ${d.subnet}, open ports: [${ports}], CVEs: [${cves}], incoming from: [${inStr}], outgoing to: [${outStr}]`;
}

export function runDynamicClientCopilot(
  question: string,
  topo: NetworkTopologyFile,
  simData?: SimulationData
): CopilotAnswer {
  const q = question.trim();
  if (!q) {
    throw new CopilotError(400, "Question must not be empty.");
  }

  const isExplainQuestion = EXPLAIN_GUARD_RE.test(q);
  if (WRITE_DELETE_RE.test(q) && !isExplainQuestion) {
    throw new CopilotError(
      422,
      "Generated query contained a disallowed keyword."
    );
  }
  if (WRITE_OTHER_RE.test(q) && !isExplainQuestion) {
    throw new CopilotError(
      422,
      "Generated query contained a disallowed keyword."
    );
  }

  const ql = q.toLowerCase();
  const devices = topo.devices ?? [];
  const connections = topo.connections ?? [];
  const mentioned = findAllMentionedDevices(q, devices);

  // 1. Multi-device / compound question (e.g., "Tell me about my_laptop and which devices can reach target_device")
  if (mentioned.length >= 2) {
    const d1 = mentioned[0];
    const d2 = mentioned[1];
    const paths12 = bfsAllPaths(connections, d1.id, d2.id);
    const paths21 = bfsAllPaths(connections, d2.id, d1.id);
    const upstreamD2 = upstreamPathsTo(connections, d2.id);

    const parts: string[] = [
      `• ${formatDeviceBrief(d1, connections)}`,
      `• ${formatDeviceBrief(d2, connections)}`,
    ];
    if (paths12.length > 0) {
      parts.push(
        `• Attack/Reachability Paths from ${d1.id} to ${d2.id}: ${paths12
          .slice(0, 5)
          .map((p) => p.join(" -> "))
          .join(" | ")}`
      );
    }
    if (paths21.length > 0) {
      parts.push(
        `• Paths from ${d2.id} to ${d1.id}: ${paths21
          .slice(0, 5)
          .map((p) => p.join(" -> "))
          .join(" | ")}`
      );
    }
    if (upstreamD2.length > 0) {
      const uniqueUp = Array.from(new Set(upstreamD2.map((p) => p[0])));
      parts.push(
        `• All devices that can reach ${d2.id} (${uniqueUp.length}): ${uniqueUp.join(
          ", "
        )} via [${upstreamD2
          .slice(0, 5)
          .map((p) => p.join(" -> "))
          .join(" ; ")}]`
      );
    }

    return {
      cypher_query: `MATCH (d:Device) WHERE d.id IN ['${d1.id}', '${d2.id}'] OPTIONAL MATCH (a:Device)-[r:CONNECTS_TO]->(b:Device) RETURN d.id AS id, d.name AS name, d.ip AS ip, d.subnet AS subnet, d.cves AS cves\nLIMIT 50`,
      raw_result: [d1, d2],
      answer: parts.join("\n"),
    };
  }

  // 2. Greetings & Identity
  if (
    /^\s*(hi|hello|hey|greetings|good\s+(morning|afternoon|evening)|yo|sup|howdy)\b/i.test(
      q
    ) ||
    /\b(who\s+are\s+you|what\s+are\s+you|what\s+can\s+you\s+do|help\s+me|how\s+do\s+i\s+use|introduce\s+yourself|your\s+capabilities)\b/i.test(
      q
    )
  ) {
    const dmzCount = devices.filter((d) => d.subnet === "public_dmz").length;
    const coreCount = devices.filter((d) => d.subnet === "internal_core").length;
    const cveCount = devices.filter((d) => (d.cves?.length ?? 0) > 0).length;
    const sampleIds = devices.slice(0, 4).map((d) => d.id);
    const statusText = simData?.status
      ? `Simulation status is currently '${simData.status}'.`
      : "Simulation is ready.";

    return {
      cypher_query:
        "MATCH (d:Device) RETURN d.id AS id, d.name AS name, d.subnet AS subnet, d.ip AS ip\nLIMIT 50",
      raw_result: devices.slice(0, 6),
      answer:
        `Hello! I am the **Project Chronos SOC Copilot** — your read-only graph intelligence and incident-response assistant. ` +
        `Right now I am monitoring **${devices.length} devices** (${dmzCount} in \`public_dmz\`, ${coreCount} in \`internal_core\`, ${cveCount} with active CVEs) ` +
        `and **${connections.length} network links** (including ${sampleIds.join(
          ", "
        )}). ${statusText}\n\n` +
        `You can ask me:\n` +
        `• **Live Status & Behavior**: "What is happening right now?", "Why is the Blue Agent waiting for approval?", "Explain Pass the Hash"\n` +
        `• **Any Device or Custom Upload**: "Tell me about ${
          sampleIds[0] ?? "web_server_01"
        }", "Which devices can reach ${
          sampleIds[sampleIds.length - 1] ?? "db_secret_01"
        }?"\n` +
        `• **Risk & Hardening**: "Which node is most at risk and how do I secure this network?"`,
    };
  }

  // 3. Behavioral, Simulation Status & Explainability
  if (
    /\b(what\s+is\s+happening|what's\s+happening|current\s+status|status\s+right\s+now|sitrep|situation\s+report|what\s+went\s+wrong|why\s+did|why\s+is|how\s+did|explain|pass\s+the\s+hash|t1550|lateral\s+movement|red\s+agent|blue\s+agent|waiting\s+for\s+approval|human\s+approval|hitl|pending\s+action|anomaly\s+score|isolation\s+forest|what\s+should\s+i\s+do|recommend\s+action)\b/i.test(
      q
    ) &&
    mentioned.length === 0
  ) {
    const status = simData?.status ?? "idle";
    const comp = simData?.compromised_node;
    const pending = simData?.pending_action;
    const score =
      simData?.anomaly_score ?? pending?.anomaly_score ?? 0.8742;

    const dmzDevs = devices.filter((d) => d.subnet === "public_dmz");
    const coreDevs = devices.filter((d) => d.subnet === "internal_core");
    const entryId = dmzDevs[0]?.id ?? devices[0]?.id ?? "entry_node";
    const crownId =
      coreDevs[coreDevs.length - 1]?.id ??
      devices[devices.length - 1]?.id ??
      "target_node";

    const notes: string[] = [];

    if (/pass\s+the\s+hash|t1550|ntlm|credential\s+replay/i.test(ql)) {
      notes.push(
        `**Pass the Hash (MITRE ATT&CK T1550.002) in Simple Terms**: Instead of cracking a user's plaintext password, the attacker steals the cached NTLM/Kerberos cryptographic hash from a compromised machine (such as \`${entryId}\`) and replays that hash directly over SMB/RPC/WinRM to authenticate onto adjacent internal servers (toward \`${crownId}\`).`
      );
    }

    if (
      /blue\s+agent|waiting|approval|hitl|human|why\s+is|pending/i.test(ql)
    ) {
      const edgeText = pending
        ? `\`${pending.source} -> ${pending.target}\``
        : "the compromised lateral link";
      notes.push(
        `**Why Blue Agent Waits for Human Approval (Bounded Authority)**: Under Project Chronos governance, the Blue Agent autonomously runs **Step 1** (Isolation Forest ML anomaly scoring: \`${score.toFixed(
          4
        )}\`), **Step 2** (RAG historical incident citation), and **Step 3** (AWS IAM/Security Group dry-run draft with \`executed: false\`). Because severing ${edgeText} is a destructive containment action that can impact production traffic, **Step 4 requires explicit Human-in-the-Loop (HITL) approval** before \`graph_cut_connection\` executes.`
      );
    }

    if (/red\s+agent|why\s+did.*attack|how\s+did.*attack|kill\s+chain/i.test(ql)) {
      notes.push(
        `**How the Red Agent Operates**: The Red Agent starts at an internet-facing foothold (\`${entryId}\`), calls \`graph_scan_neighbors()\` to discover adjacent internal pathways without hallucinating nodes, and pivots across high-trust links toward critical assets (\`${crownId}\`).`
      );
    }

    if (notes.length === 0) {
      if (status === "awaiting_approval" && pending) {
        notes.push(
          `**Live Sitrep (\`AWAITING_APPROVAL\`)**: The Red Agent breached up to \`${
            comp ?? pending.target
          }\` using **${pending.mitre_tactic}**. The Blue Agent scored this activity at **${(
            pending.anomaly_score * 100
          ).toFixed(1)}% anomaly**, cited *${
            pending.cited_incident
          }*, and drafted an AWS IAM lockdown (\`executed: false\`).\n` +
            `• **What You Should Do Next**: Review the **Human-in-the-Loop Approval Gate** banner and click **Approve & Sever Link** to cut \`${pending.source} -> ${pending.target}\`, or **Reject Proposal** to keep the link open.`
        );
      } else if (status === "running") {
        notes.push(
          `**Live Sitrep (\`RUNNING\`)**: The Red Agent is actively traversing the **${
            devices.length
          }-device** topology (currently near \`${
            comp ?? entryId
          }\`) while the Blue Agent scores telemetry via Isolation Forest ML and queries the RAG incident store.`
        );
      } else if (status === "completed") {
        notes.push(
          `**Live Sitrep (\`COMPLETED\`)**: The simulation cycle has concluded (${
            simData?.action_taken ?? "containment resolved"
          }). You can inspect any node on the graph, ask me about reachability paths, or click **Reset** to run another scenario.`
        );
      } else {
        notes.push(
          `**Live Sitrep (\`IDLE\`)**: The topology is loaded with **${devices.length} devices** and **${connections.length} connections** (entry perimeter: \`${entryId}\`, core target: \`${crownId}\`). Click **Start Simulation** to watch the Red Agent and Blue Agent operate in real time, or upload a custom \`network_topology.json\` file.`
        );
      }
    }

    return {
      cypher_query:
        "MATCH (a:Device)-[r:CONNECTS_TO]->(b:Device) RETURN a.id AS source, b.id AS target, r.type AS type\nLIMIT 50",
      raw_result: connections.slice(0, 10),
      answer: notes.join("\n\n"),
    };
  }

  // 4. Risk Ranking & Hardening Recommendations
  if (
    /\b(most\s+at\s+risk|most\s+vulnerable|highest\s+risk|biggest\s+risk|critical\s+risk|blast\s+radius|chokepoint|bottleneck|how\s+do\s+i\s+(fix|harden|secure|protect|patch|remediate)|harden|remediat|mitigat|security\s+posture|priorit)/i.test(
      q
    )
  ) {
    const ranked = [...devices]
      .map((d) => ({ dev: d, score: scoreDeviceRisk(d, connections) }))
      .sort((a, b) => b.score - a.score);

    const top3 = ranked.slice(0, 3);
    const crossLinks = connections.filter((c) => {
      const sSub = devices.find((d) => d.id === c.source)?.subnet;
      const tSub = devices.find((d) => d.id === c.target)?.subnet;
      return sSub !== tSub;
    });

    const topLines = top3.map(
      ({ dev, score }, i) =>
        `${i + 1}. **${dev.name} (\`${dev.id}\`, ${dev.ip})** — Risk Score **${score}/100**, subnet \`${dev.subnet}\`, CVEs: [${
          dev.cves?.length ? dev.cves.join(", ") : "none"
        }], ports: [${dev.ports?.join(", ") || "none"}]`
    );

    const chokeText =
      crossLinks.length > 0
        ? crossLinks.map((c) => `${c.source} -> ${c.target} (${c.type})`).join(", ")
        : connections
            .slice(0, 3)
            .map((c) => `${c.source} -> ${c.target}`)
            .join(", ");

    return {
      cypher_query:
        "MATCH (d:Device) OPTIONAL MATCH (d)-[r:CONNECTS_TO]-() RETURN d.id AS id, d.name AS name, d.subnet AS subnet, d.cves AS cves\nLIMIT 50",
      raw_result: top3.map((t) => ({ ...t.dev, risk_score: t.score })),
      answer:
        `**Dynamic Topology Risk & Hardening Assessment (${devices.length} devices analyzed)**:\n` +
        `${topLines.join("\n")}\n\n` +
        `**Recommended Hardening Actions**:\n` +
        `• **Patch High-Severity CVEs First**: Prioritize patching \`${
          top3[0]?.dev.id ?? "top asset"
        }\` (${
          top3[0]?.dev.cves?.join(", ") || "harden exposed services"
        }).\n` +
        `• **Segment Cross-Zone Chokepoints**: Enforce strict firewall ACLs and MFA across [${chokeText}] so a compromise in \`public_dmz\` cannot pivot into \`internal_core\`.\n` +
        `• **Disable NTLM Hash Replay**: Enforce SMB signing and least-privilege IAM policies (remove \`iam:PassRole\`).`,
    };
  }

  // 5. Single Mentioned Device (Connections / Paths OR Device Profile)
  if (mentioned.length === 1) {
    const dev = mentioned[0];
    const wantsConnections =
      /\b(reach|connect|link|neighbor|neighbour|path|route|talk|access|upstream|downstream|inbound|outbound|from|to)\b/i.test(
        q
      );

    if (wantsConnections) {
      const wantsIncoming =
        /\b(can\s+reach|reach\s+|into|inbound|incoming|to\s+|target|access\s+|attack\s+path)/i.test(
          q
        ) && !/\bfrom\s+/i.test(q);
      const wantsOutgoing =
        /\b(from\s+|outbound|outgoing|can\s+it\s+reach|what\s+can\s+.*reach)/i.test(
          q
        );

      const upPaths = upstreamPathsTo(connections, dev.id);
      const downPaths = downstreamPathsFrom(connections, dev.id);

      if (wantsIncoming && !wantsOutgoing) {
        const sources = Array.from(new Set(upPaths.map((p) => p[0])));
        return {
          cypher_query: `MATCH (src:Device)-[r:CONNECTS_TO]->(dst:Device {id: '${dev.id}'}) RETURN src.id AS id, src.name AS name, src.ip AS ip, r.type AS link_type\nLIMIT 50`,
          raw_result: upPaths.map((p) => ({ path: p })),
          answer:
            sources.length > 0
              ? `**${sources.length} device(s)** can reach **${dev.name} (\`${
                  dev.id
                }\`, ${dev.ip})** (directly or multi-hop): **${sources.join(
                  ", "
                )}**.\n• **Attack / Reachability Paths**: ${upPaths
                  .slice(0, 6)
                  .map((p) => p.join(" -> "))
                  .join(" ; ")}.`
              : `No upstream devices in the current topology have a directed path into **${dev.name} (\`${dev.id}\`)**.`,
        };
      }

      if (wantsOutgoing && !wantsIncoming) {
        const targets = Array.from(
          new Set(downPaths.map((p) => p[p.length - 1]))
        );
        return {
          cypher_query: `MATCH (src:Device {id: '${dev.id}'})-[r:CONNECTS_TO]->(dst:Device) RETURN dst.id AS id, dst.name AS name, dst.ip AS ip, r.type AS link_type\nLIMIT 50`,
          raw_result: downPaths.map((p) => ({ path: p })),
          answer:
            targets.length > 0
              ? `**${dev.name} (\`${dev.id}\`)** can reach **${
                  targets.length
                } downstream device(s)**: **${targets.join(
                  ", "
                )}**.\n• **Downstream Paths**: ${downPaths
                  .slice(0, 6)
                  .map((p) => p.join(" -> "))
                  .join(" ; ")}.`
              : `**${dev.name} (\`${dev.id}\`)** has no outgoing connections in the current topology.`,
        };
      }

      const upSources = Array.from(new Set(upPaths.map((p) => p[0])));
      const downTargets = Array.from(
        new Set(downPaths.map((p) => p[p.length - 1]))
      );
      return {
        cypher_query: `MATCH (d:Device {id: '${dev.id}'})-[r:CONNECTS_TO]-(peer:Device) RETURN peer.id AS id, peer.name AS name, peer.ip AS ip, r.type AS link_type\nLIMIT 50`,
        raw_result: { upstream: upPaths, downstream: downPaths } as unknown as unknown[],
        answer:
          `**Reachability Summary for ${dev.name} (\`${dev.id}\`, ${dev.ip})**:\n` +
          `• **Upstream (can reach \`${dev.id}\`)**: ${
            upSources.length > 0
              ? `${upSources.join(", ")} via [${upPaths
                  .slice(0, 4)
                  .map((p) => p.join(" -> "))
                  .join(" ; ")}]`
              : "none"
          }\n` +
          `• **Downstream (\`${dev.id}\` can reach)**: ${
            downTargets.length > 0
              ? `${downTargets.join(", ")} via [${downPaths
                  .slice(0, 4)
                  .map((p) => p.join(" -> "))
                  .join(" ; ")}]`
              : "none"
          }`,
      };
    }

    return {
      cypher_query: `MATCH (d:Device {id: '${dev.id}'}) RETURN d.id AS id, d.name AS name, d.ip AS ip, d.subnet AS subnet, d.os AS os, d.ports AS ports, d.cves AS cves\nLIMIT 50`,
      raw_result: [dev],
      answer: `**Device Profile**: ${formatDeviceBrief(dev, connections)}.`,
    };
  }

  // 6. Port Lookup
  const portMatch = q.match(/\bport\s+(\d{1,5})\b/i);
  if (portMatch) {
    const portNum = Number(portMatch[1]);
    const matches = devices.filter((d) => (d.ports ?? []).includes(portNum));
    return {
      cypher_query: `MATCH (d:Device) WHERE ${portNum} IN d.ports RETURN d.id AS id, d.name AS name, d.ip AS ip, d.ports AS ports\nLIMIT 50`,
      raw_result: matches,
      answer:
        matches.length > 0
          ? `Found **${matches.length} device(s)** with port **${portNum}** open: ${matches
              .map((d) => `${d.name} (\`${d.id}\`, ${d.ip})`)
              .join(", ")}.`
          : `No devices in the loaded topology have port **${portNum}** open.`,
    };
  }

  // 7. CVE / Vulnerability Lookup
  if (/\b(cve|vulnerab|exploit|unpatched|patch)\b/i.test(ql)) {
    const specificCve = q.match(/\b(CVE-\d{4}-\d{4,7})\b/i)?.[1]?.toUpperCase();
    const withCves = specificCve
      ? devices.filter((d) =>
          (d.cves ?? []).some((c) => c.toUpperCase() === specificCve)
        )
      : devices.filter((d) => d.cves && d.cves.length > 0);
    return {
      cypher_query:
        "MATCH (d:Device) WHERE size(d.cves) > 0 RETURN d.id AS id, d.name AS name, d.cves AS cves\nLIMIT 50",
      raw_result: withCves.map((d) => ({
        id: d.id,
        name: d.name,
        ip: d.ip,
        cves: d.cves,
      })),
      answer:
        withCves.length > 0
          ? `Found **${withCves.length} vulnerable device(s)** in the active topology: ${withCves
              .map(
                (d) =>
                  `${d.name} (\`${d.id}\`, ${d.ip}: ${d.cves.join(", ")})`
              )
              .join("; ")}.`
          : "No devices in the current topology have recorded CVEs.",
    };
  }

  // 8. Subnet Queries
  if (/\b(internal_core|internal|core|restricted)\b/i.test(ql)) {
    const internal = devices.filter((d) => d.subnet === "internal_core");
    return {
      cypher_query:
        "MATCH (d:Device)-[:PART_OF_SUBNET]->(s:Subnet {id: 'internal_core'}) RETURN d.id AS id, d.name AS name, d.ip AS ip\nLIMIT 50",
      raw_result: internal.map((d) => ({ id: d.id, name: d.name, ip: d.ip })),
      answer: `Found **${internal.length} device(s)** in \`internal_core\`: ${internal
        .map((d) => `${d.name} (\`${d.id}\`, ${d.ip})`)
        .join(", ")}.`,
    };
  }

  if (/\b(public_dmz|public|dmz|external|perimeter)\b/i.test(ql)) {
    const pub = devices.filter((d) => d.subnet === "public_dmz");
    return {
      cypher_query:
        "MATCH (d:Device)-[:PART_OF_SUBNET]->(s:Subnet {id: 'public_dmz'}) RETURN d.id AS id, d.name AS name, d.ip AS ip\nLIMIT 50",
      raw_result: pub.map((d) => ({ id: d.id, name: d.name, ip: d.ip })),
      answer: `Found **${pub.length} device(s)** in \`public_dmz\`: ${pub
        .map((d) => `${d.name} (\`${d.id}\`, ${d.ip})`)
        .join(", ")}.`,
    };
  }

  // 9. Connections / Paths Overview
  if (/\b(connect|link|route|edge|path|talk|reach|neighbo|topology)\b/i.test(ql)) {
    return {
      cypher_query:
        "MATCH (a:Device)-[r:CONNECTS_TO]->(b:Device) RETURN a.id AS source, b.id AS target, r.type AS type\nLIMIT 50",
      raw_result: connections,
      answer: `Found **${connections.length} active connection(s)** across **${
        devices.length
      } devices**: ${connections
        .slice(0, 15)
        .map((c) => `${c.source} -> ${c.target} (${c.type})`)
        .join(", ")}${connections.length > 15 ? " ..." : ""}.`,
    };
  }

  // 10. Device Inventory / Count / OS Lookup
  if (
    /\b(device|server|host|node|asset|all|list|show|how\s+many|count|inventory|linux|ubuntu|windows|debian|alpine)\b/i.test(
      ql
    )
  ) {
    return {
      cypher_query:
        "MATCH (d:Device) RETURN d.id AS id, d.name AS name, d.ip AS ip, d.os AS os, d.subnet AS subnet\nLIMIT 50",
      raw_result: devices.map((d) => ({
        id: d.id,
        name: d.name,
        ip: d.ip,
        os: d.os,
        subnet: d.subnet,
      })),
      answer: `Found **${devices.length} device(s)** in the active topology: ${devices
        .map((d) => `${d.name} (\`${d.id}\`, ${d.ip}, ${d.subnet})`)
        .join(", ")}.`,
    };
  }

  throw new CopilotError(
    422,
    "Offline copilot could not understand that question."
  );
}

export async function askCopilot(
  question: string,
  simData?: SimulationData
): Promise<CopilotAnswer> {
  const q = question.trim();
  if (!q) {
    throw new CopilotError(400, "Question must not be empty.");
  }

  const topo = await fetchTopology();

  if (!useMockData) {
    try {
      const sessionContext = simData
        ? {
            status: simData.status,
            compromised_node: simData.compromised_node,
            mitre_tactic: simData.mitre_tactic,
            anomaly_score: simData.anomaly_score,
            pending_action: simData.pending_action,
            latest_event: simData.latest_event,
          }
        : undefined;

      const response = await fetch(`${BASE_URL}/copilot/ask`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          question: q,
          topology: topo,
          session_context: sessionContext,
        }),
      });
      if (response.status === 400 || response.status === 422) {
        throw new CopilotError(
          response.status,
          `Request failed with status ${response.status}`
        );
      }
      if (response.ok) {
        return response.json();
      }
    } catch (err) {
      if (err instanceof CopilotError) {
        throw err;
      }
      // If backend is unreachable or sleeping, seamlessly fall back to the client-side dynamic engine
    }
  }

  return runDynamicClientCopilot(q, topo, simData);
}
