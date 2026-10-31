"""Dynamic Offline & Fallback SOC Copilot Engine (NL -> Cypher + Behavioral & Topology Reasoning).

Used when GROQ_API_KEY is missing / the LLM call fails, and whenever Neo4j is unavailable.
Also powers conversational/behavioral explainability questions and adapts dynamically to ANY
uploaded `network_topology.json` (whether the 19-device enterprise twin, 6-device sample, or
a custom home/cloud topology) plus live simulation state (`session_store`).

Every generated Cypher string is passed through `validate_cypher` by the caller, so
destructive requests are translated into the write query they imply and then REJECTED by the
same read-only validator that guards LLM output (HTTP 422).
"""
from __future__ import annotations

from collections import deque
import re
from typing import Any, Optional

_WRITE_DELETE = re.compile(
    r"\b(delete|remove|drop|destroy|wipe|sever|disconnect|cut|erase|truncate)\b",
    re.I,
)
_WRITE_OTHER = re.compile(
    r"\b(create|insert|merge|update|modify|rename|overwrite)\b",
    re.I,
)

# Questions asking *why* or *how* containment works should not be mistaken for destructive commands
_EXPLAIN_GUARD = re.compile(
    r"^\s*(?:why|how|what|explain|can\s+you\s+explain|tell\s+me\s+why)\b",
    re.I,
)
_EXPLICIT_IMPERATIVE_WRITE = re.compile(
    r"\b(?:delete|drop|destroy|wipe|erase|truncate|remove\s+(?:the|all|every)|create\s+(?:a|an|new)|insert|merge|overwrite)\b",
    re.I,
)

_PUBLIC = re.compile(r"\b(public|dmz|external|internet[- ]facing|perimeter)\b", re.I)
_INTERNAL = re.compile(r"\b(internal|core|secure|restricted|private)\b", re.I)

_GREETING_RE = re.compile(
    r"\b(hi|hello|hey|howdy|namaste|hola|greetings|good\s+(?:morning|afternoon|evening)|"
    r"who\s+are\s+you|what\s+are\s+you|what\s+can\s+you\s+do|help|capabilities|introduce\s+yourself)\b",
    re.I,
)

_BEHAVIORAL_RE = re.compile(
    r"\b(what\s+is\s+happening|what's\s+happening|whats\s+happening|current\s+status|simulation\s+status|"
    r"sitrep|situation|why\s+did|why\s+is|how\s+does|explain|pass[- ]the[- ]hash|t1550|lateral\s+movement|"
    r"red\s+agent|blue\s+agent|waiting\s+for|approval|hitl|human[- ]in[- ]the[- ]loop|anomaly\s+score|"
    r"isolation\s+forest|rag\b|cited\s+incident|aws\s+remediation|bounded\s+authority|what\s+should\s+i\s+do|"
    r"next\s+step|attack\s+summary|incident\s+report)\b",
    re.I,
)

_RISK_HARDEN_RE = re.compile(
    r"\b(most\s+(?:at\s+risk|vulnerable|critical|dangerous|exposed)|highest\s+risk|weakest|"
    r"how\s+(?:do\s+i|to|can\s+i|should\s+i)\s+(?:fix|harden|secure|protect|defend|mitigate|patch|remediate)|"
    r"harden|remediat|mitigat|blast\s+radius|chokepoint|bottleneck|security\s+posture|recommendations?|"
    r"which\s+(?:node|device|host|server|asset)\s+is\s+(?:most|at\s+risk|vulnerable))\b",
    re.I,
)

_STOPWORDS = {
    "the", "and", "for", "with", "from", "into", "that", "this", "what", "which",
    "who", "how", "why", "can", "does", "are", "all", "any", "device", "devices",
    "node", "nodes", "server", "servers", "host", "hosts", "machine", "system",
    "network", "subnet", "reach", "connect", "connected", "connections", "tell",
    "about", "show", "list", "inspect",
}


def _esc(s: str) -> str:
    return str(s).replace("\\", "\\\\").replace("'", "\\'")


def _mentioned_devices(question: str, devices: list[dict]) -> list[dict]:
    """Find devices from the active topology mentioned by ID, name, IP, or token overlap."""
    q = question.lower()
    q_norm = re.sub(r"[_\-]+", " ", q)
    found: list[dict] = []
    seen: set[str] = set()

    for d in devices:
        did = str(d.get("id", "")).lower()
        name = str(d.get("name") or "").lower()
        name_norm = re.sub(r"[_\-]+", " ", name)
        ip = str(d.get("ip") or "").lower()

        id_tokens = [t for t in re.split(r"[_\-\s]+", did) if len(t) >= 2]
        id_token_match = len(id_tokens) >= 2 and all(
            re.search(rf"\b{re.escape(t)}\b", q_norm) for t in id_tokens
        )

        name_tokens = [
            t for t in re.split(r"[_\-\s]+", name_norm)
            if len(t) >= 3 and t not in _STOPWORDS and t not in ("db", "sql", "pc")
        ]
        # Allow matching e.g. "Classified SQL database" -> "Classified SQL DB"
        sig_name_tokens = [
            t for t in re.split(r"[_\-\s]+", name_norm)
            if len(t) >= 3 and t not in _STOPWORDS and t != "db"
        ]
        name_token_match = len(sig_name_tokens) >= 2 and all(
            re.search(rf"\b{re.escape(t)}\b", q_norm) for t in sig_name_tokens
        )

        if (
            re.search(rf"(?<![\w-]){re.escape(did)}(?![\w-])", q)
            or (len(did) >= 3 and re.sub(r"[_\-]+", " ", did) in q_norm)
            or (name and len(name) >= 3 and name in q)
            or (ip and ip in q)
            or id_token_match
            or name_token_match
            or (len(name_tokens) >= 2 and all(re.search(rf"\b{re.escape(t)}\b", q_norm) for t in name_tokens))
        ):
            if d["id"] not in seen:
                seen.add(d["id"])
                found.append(d)

    # Fallback semantic alias matching on the active topology (e.g. "database", "router", "firewall", "auth")
    if not found:
        if re.search(r"\b(database|sql|db)\b", q_norm):
            for d in devices:
                blob = f"{d.get('id', '')} {d.get('name', '')}".lower()
                if any(k in blob for k in ("db", "sql", "database", "vault")):
                    found.append(d)
                    break
        elif re.search(r"\b(router|wifi|gateway|proxy)\b", q_norm):
            for d in devices:
                blob = f"{d.get('id', '')} {d.get('name', '')}".lower()
                if any(k in blob for k in ("router", "wifi", "gw", "gateway", "proxy")):
                    found.append(d)
                    break
        elif re.search(r"\b(auth|active directory|domain controller|ldap)\b", q_norm):
            for d in devices:
                blob = f"{d.get('id', '')} {d.get('name', '')}".lower()
                if any(k in blob for k in ("auth", "dc", "domain", "directory")):
                    found.append(d)
                    break

    return found


def _bfs_all_paths(
    connections: list[dict],
    start_id: str,
    target_id: str,
    max_hops: int = 6,
) -> list[list[str]]:
    """Return simple directed paths from start_id to target_id up to max_hops."""
    adj: dict[str, list[str]] = {}
    for c in connections:
        adj.setdefault(c["source"], []).append(c["target"])

    paths: list[list[str]] = []
    queue: deque[list[str]] = deque([[start_id]])
    while queue:
        path = queue.popleft()
        last = path[-1]
        if last == target_id and len(path) > 1:
            paths.append(path)
            continue
        if len(path) > max_hops:
            continue
        for nxt in adj.get(last, []):
            if nxt not in path:
                queue.append(path + [nxt])
    return paths


def _upstream_paths_to(
    connections: list[dict],
    target_id: str,
    max_hops: int = 5,
) -> list[list[str]]:
    """Find all directed multi-hop paths that terminate at target_id."""
    rev: dict[str, list[str]] = {}
    for c in connections:
        rev.setdefault(c["target"], []).append(c["source"])

    paths: list[list[str]] = []
    queue: deque[list[str]] = deque([[target_id]])
    while queue:
        chain = queue.popleft()
        first = chain[0]
        preds = [p for p in rev.get(first, []) if p not in chain]
        if not preds or len(chain) > max_hops:
            if len(chain) > 1:
                paths.append(chain)
            continue
        for p in preds:
            new_chain = [p] + chain
            paths.append(new_chain)
            queue.append(new_chain)

    # Deduplicate and sort shortest-first, then longest complete chains
    unique: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()
    for p in sorted(paths, key=lambda x: (len(x), x)):
        t = tuple(p)
        if t not in seen:
            seen.add(t)
            unique.append(p)
    return unique


def _downstream_paths_from(
    connections: list[dict],
    source_id: str,
    max_hops: int = 5,
) -> list[list[str]]:
    """Find directed multi-hop paths starting from source_id."""
    adj: dict[str, list[str]] = {}
    for c in connections:
        adj.setdefault(c["source"], []).append(c["target"])

    paths: list[list[str]] = []
    queue: deque[list[str]] = deque([[source_id]])
    while queue:
        chain = queue.popleft()
        last = chain[-1]
        succs = [s for s in adj.get(last, []) if s not in chain]
        if not succs or len(chain) > max_hops:
            continue
        for s in succs:
            new_chain = chain + [s]
            paths.append(new_chain)
            queue.append(new_chain)
    return paths


def rule_based_plan(
    question: str,
    devices: Optional[list[dict]] = None,
    topology: Optional[dict] = None,
    session_context: Optional[dict] = None,
) -> dict:
    """Return {"intent", "cypher", ...params}. Never raises for write requests (the validator will);
    raises ValueError only if the question is empty or unintelligible gibberish."""
    q = (question or "").strip()
    ql = q.lower()

    # 1. Check destructive / mutating intent first so validate_cypher blocks with HTTP 422
    is_explain = bool(_EXPLAIN_GUARD.search(ql)) and not bool(_EXPLICIT_IMPERATIVE_WRITE.search(ql))
    if not is_explain:
        if _WRITE_DELETE.search(ql):
            return {
                "intent": "write",
                "cypher": "MATCH (a:Device)-[r:CONNECTS_TO]->(b:Device) DELETE r",
            }
        if _WRITE_OTHER.search(ql):
            return {
                "intent": "write",
                "cypher": "MATCH (n:Device) SET n.modified = true RETURN n",
            }

    if devices is None and topology is not None:
        devices = topology.get("devices", [])
    devices = devices or []
    nodes = _mentioned_devices(q, devices)
    ids = [n["id"] for n in nodes]

    # 2. Compound or specific device + reachability queries
    has_reach_kw = bool(
        re.search(
            r"connect|neighbo|talk|reach|path|link|route|lateral|access|traffic|from|to\b|into|incoming|outgoing|between",
            ql,
        )
    )
    has_inspect_kw = bool(
        re.search(r"\b(tell\s+me\s+about|inspect|details|info|describe|profile|what\s+is)\b", ql)
    )

    if len(ids) >= 2 and (has_reach_kw or has_inspect_kw):
        return {
            "intent": "multi_device_analysis",
            "ids": ids,
            "cypher": (
                f"MATCH (d:Device) WHERE d.id IN {ids!r} "
                "OPTIONAL MATCH (a:Device)-[r:CONNECTS_TO]->(b:Device) "
                "RETURN d.id AS id, d.name AS name, d.ip AS ip, d.os AS os, d.ports AS ports, d.cves AS cves"
            ).replace('"', "'"),
        }

    # 3. Count queries
    if re.search(r"\bhow many\b|\bcount\b|\bnumber of\b", ql):
        if re.search(r"connection|link|route|edge", ql):
            return {
                "intent": "count_connections",
                "cypher": "MATCH (:Device)-[r:CONNECTS_TO]->(:Device) RETURN count(r) AS connections",
            }
        return {
            "intent": "count_devices",
            "cypher": "MATCH (d:Device) RETURN count(d) AS devices",
        }

    # 4. Behavioral / Simulation Status / Explainability questions
    if _BEHAVIORAL_RE.search(ql) and not (ids and has_reach_kw and not is_explain):
        return {
            "intent": "behavioral_explain",
            "ids": ids,
            "cypher": (
                "MATCH (a:Device)-[r:CONNECTS_TO]->(b:Device) "
                "RETURN a.id AS source, b.id AS target, r.type AS type"
            ),
        }

    # 5. Risk, Vulnerability Ranking & Network Hardening questions
    if _RISK_HARDEN_RE.search(ql):
        return {
            "intent": "risk_and_hardening",
            "ids": ids,
            "cypher": (
                "MATCH (d:Device) "
                "RETURN d.id AS id, d.name AS name, d.ip AS ip, d.os AS os, d.ports AS ports, d.cves AS cves"
            ),
        }

    # 6. Greetings, Identity & Help
    if _GREETING_RE.search(ql) and not ids:
        return {
            "intent": "greeting",
            "cypher": "MATCH (d:Device) RETURN d.id AS id, d.name AS name, d.ip AS ip, d.os AS os",
        }

    # 7. CVE / Vulnerability queries
    if re.search(r"cve|vulnerab|exploit|unpatched", ql):
        if ids:
            return {
                "intent": "cves",
                "ids": ids,
                "cypher": (
                    f"MATCH (d:Device) WHERE d.id IN {[i for i in ids]!r} "
                    "RETURN d.id AS id, d.name AS name, d.cves AS cves"
                ).replace('"', "'"),
            }
        return {
            "intent": "cves",
            "ids": [],
            "cypher": "MATCH (d:Device) WHERE size(d.cves) > 0 RETURN d.id AS id, d.name AS name, d.cves AS cves",
        }

    # 8. Port queries (including common service names like SSH/22, HTTP/80, HTTPS/443, SMB/445, RDP/3389, SQL/1433/3306)
    port = re.search(r"\bport\s+(\d{1,5})\b|\b(\d{1,5})\s*/?\s*(?:tcp|udp)\b", ql)
    service_port_map = {
        r"\bssh\b": 22,
        r"\bdns\b": 53,
        r"\bhttp\b": 80,
        r"\bhttps\b": 443,
        r"\bsmb\b": 445,
        r"\bldap\b": 389,
        r"\brdp\b": 3389,
        r"\bmysql\b": 3306,
        r"\bmssql\b": 1433,
    }
    inferred_port: Optional[int] = None
    if port:
        inferred_port = int(port.group(1) or port.group(2))
    elif re.search(r"\b(port|ports|expose|listening|open)\b", ql):
        for pat, pnum in service_port_map.items():
            if re.search(pat, ql):
                inferred_port = pnum
                break

    if inferred_port is not None:
        return {
            "intent": "port",
            "port": inferred_port,
            "cypher": (
                f"MATCH (d:Device) WHERE {inferred_port} IN d.ports "
                "RETURN d.id AS id, d.name AS name, d.ports AS ports"
            ),
        }

    # 9. Single-device connection / reachability queries
    if ids and has_reach_kw:
        nid = _esc(ids[0])
        if re.search(
            r"\bincoming\b|\binto\b|\b(?:who|which\s+\w+|what\s+\w+)\s+(?:can\s+)?(?:reach|access|talk|connect\s+to)|"
            r"\breach\s+" + re.escape(ids[0].lower()),
            ql,
        ):
            return {
                "intent": "connections",
                "node": ids[0],
                "direction": "in",
                "cypher": (
                    f"MATCH (a:Device)-[r:CONNECTS_TO]->(b:Device {{id: '{nid}'}}) "
                    "RETURN a.id AS source, b.id AS target, r.type AS type"
                ),
            }
        if re.search(r"\boutgoing\b|\bfrom\b", ql):
            return {
                "intent": "connections",
                "node": ids[0],
                "direction": "out",
                "cypher": (
                    f"MATCH (a:Device {{id: '{nid}'}})-[r:CONNECTS_TO]->(b:Device) "
                    "RETURN a.id AS source, b.id AS target, r.type AS type"
                ),
            }
        return {
            "intent": "connections",
            "node": ids[0],
            "direction": "both",
            "cypher": (
                f"MATCH (a:Device)-[r:CONNECTS_TO]-(b:Device {{id: '{nid}'}}) "
                "RETURN a.id AS source, b.id AS target, r.type AS type"
            ),
        }

    # 10. Subnet queries
    subnet = None
    if _PUBLIC.search(ql) and not _INTERNAL.search(ql):
        subnet = "public_dmz"
    elif _INTERNAL.search(ql) and not _PUBLIC.search(ql):
        subnet = "internal_core"
    if subnet and not ids:
        return {
            "intent": "subnet",
            "subnet": subnet,
            "cypher": (
                f"MATCH (d:Device)-[:PART_OF_SUBNET]->(s:Subnet {{id: '{subnet}'}}) "
                "RETURN d.id AS id, d.name AS name, d.ip AS ip"
            ),
        }

    # 11. Specific device inspection
    if ids:
        return {
            "intent": "device",
            "ids": ids,
            "cypher": (
                f"MATCH (d:Device) WHERE d.id IN {ids!r} "
                "RETURN d.id AS id, d.name AS name, d.ip AS ip, d.os AS os, d.ports AS ports, d.cves AS cves"
            ).replace('"', "'"),
        }

    # 12. General topology / connection / device overview queries
    if re.search(r"connection|link|route|edge|path|corridor", ql):
        return {
            "intent": "all_connections",
            "cypher": (
                "MATCH (a:Device)-[r:CONNECTS_TO]->(b:Device) "
                "RETURN a.id AS source, b.id AS target, r.type AS type"
            ),
        }
    if re.search(
        r"device|server|host|machine|workstation|node|asset|system|list|show|all|everything|topology|network|summary|overview|loaded|assigned",
        ql,
    ):
        return {
            "intent": "all_devices",
            "cypher": "MATCH (d:Device) RETURN d.id AS id, d.name AS name, d.ip AS ip, d.os AS os",
        }

    raise ValueError(
        "Offline copilot could not understand that question. Try asking about devices, connections, "
        "subnets, CVEs, ports, attack paths, or simulation status."
    )


def run_on_mirror(plan: dict, topology: dict) -> list[dict]:
    """Execute a rule-based plan's intent against {"devices": [...], "connections": [...]}."""
    devices, conns = topology.get("devices", []), topology.get("connections", [])
    by_id = {d["id"]: d for d in devices}
    intent = plan["intent"]
    pick = lambda d, *keys: {k: d.get(k) for k in keys}  # noqa: E731

    if intent == "count_devices":
        return [{"devices": len(devices)}]
    if intent == "count_connections":
        return [{"connections": len(conns)}]
    if intent == "cves":
        ids = plan.get("ids")
        rows = [d for d in devices if (d["id"] in ids if ids else d.get("cves"))]
        return [{"id": d["id"], "name": d.get("name"), "cves": d.get("cves", [])} for d in rows]
    if intent == "port":
        return [
            {"id": d["id"], "name": d.get("name"), "ports": d.get("ports", [])}
            for d in devices
            if plan["port"] in (d.get("ports") or [])
        ]
    if intent == "connections":
        n, direction = plan["node"], plan["direction"]
        rows = []
        for c in conns:
            if direction in ("out", "both") and c["source"] == n:
                rows.append({"source": c["source"], "target": c["target"], "type": c.get("type")})
            elif direction in ("in", "both") and c["target"] == n:
                rows.append({"source": c["source"], "target": c["target"], "type": c.get("type")})
        return rows
    if intent == "subnet":
        return [pick(d, "id", "name", "ip") for d in devices if d.get("subnet") == plan["subnet"]]
    if intent in ("device", "multi_device_analysis"):
        return [
            pick(by_id[i], "id", "name", "ip", "os", "subnet", "ports", "cves")
            for i in plan.get("ids", [])
            if i in by_id
        ]
    if intent in ("all_connections", "behavioral_explain"):
        return [{"source": c["source"], "target": c["target"], "type": c.get("type")} for c in conns]
    if intent in ("all_devices", "greeting", "risk_and_hardening"):
        return [pick(d, "id", "name", "ip", "os", "subnet", "ports", "cves") for d in devices]
    raise ValueError(f"Unsupported offline intent: {intent}")


def _describe_device_rich(d: dict, conns: list[dict]) -> str:
    did = d["id"]
    name = d.get("name") or did
    ip = d.get("ip") or "unknown IP"
    os_name = d.get("os") or "unknown OS"
    subnet = d.get("subnet") or "internal_core"
    ports = d.get("ports") or []
    cves = d.get("cves") or []

    inbound = [f"{c['source']} ({c.get('type', 'LINK')})" for c in conns if c["target"] == did]
    outbound = [f"{c['target']} ({c.get('type', 'LINK')})" for c in conns if c["source"] == did]

    ports_txt = ", ".join(str(p) for p in ports) if ports else "none"
    cves_txt = ", ".join(cves) if cves else "0 known CVEs"
    in_txt = ", ".join(inbound) if inbound else "none (entry/isolated)"
    out_txt = ", ".join(outbound) if outbound else "none (sink/terminal)"

    return (
        f"{name} ({did}) — IP: {ip} | Subnet: {subnet} | OS: {os_name} | "
        f"Open Ports: [{ports_txt}] | CVEs: [{cves_txt}] | "
        f"Inbound from: {in_txt} | Outbound to: {out_txt}"
    )


def _load_active_session(session_context: Optional[dict] = None) -> dict:
    if session_context:
        return session_context
    try:
        from backend.db.session_store import get_current_session

        return get_current_session() or {}
    except Exception:  # noqa: BLE001
        return {}


def summarize_offline(
    question: str,
    plan: Optional[dict],
    records: list[dict[str, Any]],
    topology: Optional[dict] = None,
    session_context: Optional[dict] = None,
) -> str:
    """Dynamic, context-aware plain-language answer grounded in the active topology and simulation state."""
    if topology is None:
        try:
            from backend.db import topology_store

            topology = topology_store.get_topology()
        except Exception:  # noqa: BLE001
            topology = {"devices": [], "connections": []}

    devices: list[dict] = topology.get("devices", [])
    conns: list[dict] = topology.get("connections", [])
    by_id: dict[str, dict] = {d["id"]: d for d in devices}
    session = _load_active_session(session_context)

    intent = (plan or {}).get("intent", "")
    ql = (question or "").lower()

    # 1. GREETING / HELP / IDENTITY
    if intent == "greeting":
        dmz = [d for d in devices if d.get("subnet") == "public_dmz"]
        core = [d for d in devices if d.get("subnet") == "internal_core"]
        sample_names = ", ".join(f"{d.get('name', d['id'])} ({d['id']})" for d in devices[:4])
        status = session.get("status", "idle")
        pa = session.get("pending_action")
        sim_note = (
            f"Simulation is currently AWAITING APPROVAL to sever {pa['source']} -> {pa['target']}."
            if status == "awaiting_approval" and pa
            else f"Simulation status is currently '{status}'."
        )
        return (
            f"Hello! I am the Project Chronos SOC Copilot — your read-only graph & incident intelligence assistant. "
            f"Right now, the active topology has {len(devices)} device(s) ({len(dmz)} in public_dmz, "
            f"{len(core)} in internal_core) and {len(conns)} network connection(s), including {sample_names}. "
            f"{sim_note} You can ask me about any device, multi-hop attack paths, CVE exposures, why the Red/Blue "
            f"agents acted, or how to harden this network!"
        )

    # 2. BEHAVIORAL / SIMULATION STATUS / EXPLAINABILITY
    if intent == "behavioral_explain":
        status = session.get("status", "idle")
        pa = session.get("pending_action")
        comp = session.get("compromised_node")
        score = session.get("anomaly_score") or (pa.get("anomaly_score") if pa else None)
        cited = pa.get("cited_incident") if pa else None
        action_taken = session.get("action_taken")

        parts: list[str] = []
        if re.search(r"pass[- ]the[- ]hash|t1550|lateral\s+movement|red\s+agent|why\s+did.*attack", ql):
            entry = next((d["id"] for d in devices if d.get("subnet") == "public_dmz"), devices[0]["id"] if devices else "entry_node")
            target = (pa or {}).get("target") or comp or (devices[-1]["id"] if devices else "core_asset")
            parts.append(
                f"Red Agent Behavior (MITRE T1550.002 — Pass-the-Hash Lateral Movement): "
                f"In simple terms, instead of cracking a password, the attacker steals a cached NTLM/Kerberos credential "
                f"hash from an initial perimeter foothold (such as '{entry}') and replays that hash to authenticate "
                f"directly onto deeper internal nodes (targeting '{target}') via graph_scan_neighbors()."
            )

        if re.search(r"blue\s+agent|approval|waiting|hitl|human|anomaly|isolation\s+forest|rag|bounded", ql):
            score_str = f"{float(score):.4f}" if score is not None else "0.8230 (ANOMALY)"
            cite_str = cited or "Incident 2025-02: Reverse Proxy Credential Replay & Lateral Movement to Core Auth"
            edge_str = f"{pa['source']} -> {pa['target']}" if pa else "the compromised lateral corridor"
            parts.append(
                f"Blue Agent & Human-in-the-Loop Governance: The Blue Agent operates under Bounded Authority. "
                f"It verified the intrusion with the Isolation Forest ML model (anomaly_score={score_str}), "
                f"grounded its response in historical precedent via RAG ('{cite_str}'), and drafted an AWS "
                f"isolation plan (executed=False). However, it cannot sever '{edge_str}' on its own — a human "
                f"analyst must click Approve (POST /approve_action) to execute the graph cut."
            )

        if not parts:
            if status == "awaiting_approval" and pa:
                parts.append(
                    f"Live Situation Report: The simulation is currently in 'awaiting_approval'. "
                    f"The Red Agent pivoted toward '{pa['target']}' ({pa.get('mitre_tactic', 'T1550.002')}). "
                    f"The Blue Agent scored the anomaly at {float(pa.get('anomaly_score', 0.82)):.4f}, cited "
                    f"'{pa.get('cited_incident', 'historical incident')}', and proposes severing "
                    f"{pa['source']} -> {pa['target']}. Approve the action in the HITL panel to isolate the threat."
                )
            elif status == "completed":
                parts.append(
                    f"Live Situation Report: Simulation cycle completed. Action taken: {action_taken or 'Resolved by analyst'}. "
                    f"The active topology currently has {len(devices)} devices and {len(conns)} active connections remaining."
                )
            elif status == "running":
                parts.append(
                    f"Live Situation Report: Simulation is actively running across {len(devices)} devices and "
                    f"{len(conns)} connections. Compromised foothold: {comp or 'scanning perimeter'}."
                )
            else:
                dmz_nodes = [d["id"] for d in devices if d.get("subnet") == "public_dmz"]
                cve_nodes = [d["id"] for d in devices if d.get("cves")]
                parts.append(
                    f"Live Situation Report: The simulation is currently 'idle' across {len(devices)} devices "
                    f"({len(dmz_nodes)} DMZ entry node(s): {', '.join(dmz_nodes[:4]) or 'none'}) and {len(conns)} "
                    f"connections. {len(cve_nodes)} device(s) have unpatched CVEs ({', '.join(cve_nodes[:5]) or 'none'}). "
                    f"Click 'Start Simulation' to trigger a Red vs. Blue cycle."
                )

        return " ".join(parts)

    # 3. RISK ANALYSIS & NETWORK HARDENING
    if intent == "risk_and_hardening":
        if not devices:
            return "No devices are currently loaded in the topology."

        scored: list[tuple[int, dict, int, int]] = []
        for d in devices:
            did = d["id"]
            cve_cnt = len(d.get("cves") or [])
            in_deg = sum(1 for c in conns if c["target"] == did)
            out_deg = sum(1 for c in conns if c["source"] == did)
            is_core = 1 if d.get("subnet") == "internal_core" else 0
            risk_pts = cve_cnt * 25 + (in_deg + out_deg) * 10 + is_core * 15
            scored.append((risk_pts, d, in_deg, out_deg))

        scored.sort(key=lambda x: x[0], reverse=True)
        top = scored[:3]
        top_desc = "; ".join(
            f"{d.get('name', d['id'])} ({d['id']}, IP {d.get('ip')}, "
            f"CVEs: {', '.join(d.get('cves') or []) or 'none'}, "
            f"links: {in_deg} in / {out_deg} out)"
            for _pts, d, in_deg, out_deg in top
        )

        # Find DMZ -> Internal Core bridge connections
        bridges = [
            f"{c['source']} -> {c['target']} ({c.get('type', 'LINK')})"
            for c in conns
            if by_id.get(c["source"], {}).get("subnet") == "public_dmz"
            and by_id.get(c["target"], {}).get("subnet") == "internal_core"
        ]
        bridge_txt = (
            f" Critical DMZ-to-Core choke points: {', '.join(bridges[:4])}."
            if bridges
            else ""
        )

        return (
            f"Dynamic Risk & Hardening Assessment ({len(devices)} devices analyzed): "
            f"Highest-exposure asset(s): {top_desc}.{bridge_txt} "
            f"Recommended hardening: (1) Patch CVEs on {', '.join(x[1]['id'] for x in top if x[1].get('cves')) or top[0][1]['id']}; "
            f"(2) Enforce MFA and segment lateral routes across {bridges[0] if bridges else 'high-degree internal hubs'}; "
            f"(3) Use the HITL Approval Gate to sever compromised paths during active intrusion."
        )

    # 4. MULTI-DEVICE / COMPOUND ANALYSIS (e.g. "Tell me about my_laptop and which devices can reach target_device")
    if intent == "multi_device_analysis":
        ids = plan.get("ids", [])
        segments: list[str] = []
        for did in ids:
            if did in by_id:
                segments.append(_describe_device_rich(by_id[did], conns))

        # Check direct & multi-hop paths between any pair, plus upstream reachability to the last mentioned device
        if len(ids) >= 2:
            src_id, tgt_id = ids[0], ids[-1]
            direct_paths = _bfs_all_paths(conns, src_id, tgt_id)
            if direct_paths:
                formatted = [" -> ".join(p) for p in direct_paths[:4]]
                segments.append(f"Path(s) from {src_id} to {tgt_id}: {'; '.join(formatted)}.")
            upstream = _upstream_paths_to(conns, tgt_id)
            if upstream:
                up_chains = [" -> ".join(p) for p in upstream[:5]]
                reachable_nodes = sorted({n for p in upstream for n in p if n != tgt_id})
                segments.append(
                    f"Devices that can reach {tgt_id} ({len(reachable_nodes)}: {', '.join(reachable_nodes)}): "
                    f"{'; '.join(up_chains)}."
                )

        return " | ".join(segments) if segments else "No matching devices found in the current topology."

    # 5. SINGLE-DEVICE CONNECTIONS & MULTI-HOP REACHABILITY
    if intent == "connections":
        node_id = plan["node"]
        direction = plan["direction"]
        direct_pairs = [f"{r['source']} -> {r['target']} ({r.get('type', 'LINK')})" for r in records[:8]]

        if direction == "in":
            upstream = _upstream_paths_to(conns, node_id)
            reachable_sources = sorted({n for p in upstream for n in p if n != node_id})
            if not records and not upstream:
                return f"No devices in the current topology have a directed route reaching {node_id}."
            chain_txt = "; ".join(" -> ".join(p) for p in upstream[:5])
            return (
                f"Found {len(records)} direct incoming connection(s) to {node_id}: "
                f"{', '.join(direct_pairs) if direct_pairs else 'none'}. "
                f"All devices that can reach {node_id} (direct + multi-hop: {', '.join(reachable_sources)}): {chain_txt}."
            )

        if direction == "out":
            downstream = _downstream_paths_from(conns, node_id)
            if not records:
                return f"{node_id} has no outbound connections in the current topology."
            chain_txt = "; ".join(" -> ".join(p) for p in downstream[:5])
            return (
                f"Found {len(records)} outbound connection(s) from {node_id}: {', '.join(direct_pairs)}. "
                f"Downstream reachability paths: {chain_txt}."
            )

        # direction == "both"
        if not records:
            return f"{node_id} currently has 0 active connections (isolated)."
        upstream = _upstream_paths_to(conns, node_id)
        downstream = _downstream_paths_from(conns, node_id)
        extra = []
        if upstream:
            extra.append("Upstream paths: " + "; ".join(" -> ".join(p) for p in upstream[:3]))
        if downstream:
            extra.append("Downstream paths: " + "; ".join(" -> ".join(p) for p in downstream[:3]))
        extra_str = (" " + " | ".join(extra) + ".") if extra else ""
        return f"Found {len(records)} connection(s) involving {node_id}: {', '.join(direct_pairs)}.{extra_str}"

    # 6. SPECIFIC DEVICE INSPECTOR
    if intent == "device":
        if not records:
            return "Nothing in the current topology matched that device."
        descriptions = [
            _describe_device_rich(by_id.get(r["id"], r), conns)
            for r in records[:5]
        ]
        return " | ".join(descriptions)

    if not records:
        return "Nothing in the current topology matched that question."

    if intent.startswith("count_"):
        key, val = next(iter(records[0].items()))
        return f"There are {val} {key} in the current topology."

    if intent == "all_connections":
        pairs = [f"{r['source']} -> {r['target']} ({r.get('type', 'LINK')})" for r in records[:10]]
        more = f" (+{len(records) - 10} more)" if len(records) > 10 else ""
        return f"Found {len(records)} active connection(s) in the current topology: " + ", ".join(pairs) + more + "."

    if intent == "cves":
        parts = [f"{r['id']} ({', '.join(r['cves'])})" for r in records[:10] if r.get("cves")]
        return (
            f"{len(parts)} device(s) have known CVEs in the current topology: " + ", ".join(parts) + "."
            if parts
            else "The matching devices have no recorded CVEs."
        )

    if intent == "port":
        return (
            f"{len(records)} device(s) expose port {plan['port']}: "
            + ", ".join(f"{r['id']} ({r.get('name', r['id'])})" for r in records[:10])
            + "."
        )

    if intent == "subnet":
        sub = plan.get("subnet", "subnet")
        items = [f"{r['id']} ({r.get('name', r['id'])}, {r.get('ip', '')})" for r in records[:12]]
        more = f" (+{len(records) - 12} more)" if len(records) > 12 else ""
        return f"Found {len(records)} device(s) in {sub}: " + ", ".join(items) + more + "."

    # all_devices fallback
    items = [f"{r.get('name') or r['id']} ({r['id']}, {r.get('ip', 'no-ip')})" for r in records[:12]]
    more = f" (+{len(records) - 12} more)" if len(records) > 12 else ""
    return f"Found {len(records)} device(s) in the active topology: " + ", ".join(items) + more + "."
