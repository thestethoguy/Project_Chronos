"""Offline (no-LLM) SOC Copilot: rule-based NL -> Cypher translation, mirror execution and summaries.

Used when GROQ_API_KEY is missing / the LLM call fails, and whenever Neo4j is unavailable (the
mirror cannot execute arbitrary Cypher, so it executes the *intent* behind the rule-based Cypher).
Every generated Cypher string is still passed through `validate_cypher` by the caller, so
destructive requests are translated into the write query they imply and then REJECTED by the
same read-only validator that guards LLM output.
"""
from __future__ import annotations

import re
from typing import Any, Optional

_WRITE_DELETE = re.compile(r"\b(delete|remove|drop|destroy|wipe|sever|disconnect|cut|erase|truncate)\b", re.I)
_WRITE_OTHER = re.compile(r"\b(create|insert|merge|update|modify|rename|overwrite)\b", re.I)

_PUBLIC = re.compile(r"\b(public|dmz|external|internet[- ]facing)\b", re.I)
_INTERNAL = re.compile(r"\b(internal|core|secure|restricted|private)\b", re.I)


def _esc(s: str) -> str:
    return str(s).replace("\\", "\\\\").replace("'", "\\'")


def _mentioned_devices(question: str, devices: list[dict]) -> list[dict]:
    q = question.lower()
    q_norm = re.sub(r"[_\-]+", " ", q)
    found = []
    for d in devices:
        did = d["id"].lower()
        name = (d.get("name") or "").lower()
        id_tokens = [t for t in re.split(r"[_\-\s]+", did) if len(t) >= 2]
        token_match = len(id_tokens) >= 2 and all(re.search(rf"\b{re.escape(t)}\b", q_norm) for t in id_tokens)
        if (
            re.search(rf"(?<![\w-]){re.escape(did)}(?![\w-])", q)
            or re.sub(r"[_\-]+", " ", did) in q_norm
            or (name and name in q)
            or token_match
        ):
            found.append(d)
    return found


def rule_based_plan(question: str, devices: Optional[list[dict]] = None) -> dict:
    """Return {"intent", "cypher", ...params}. Never raises for write requests (the validator will);
    raises ValueError only if the question cannot be understood at all."""
    q = (question or "").strip()
    ql = q.lower()
    if _WRITE_DELETE.search(ql):
        return {"intent": "write", "cypher": "MATCH (a:Device)-[r:CONNECTS_TO]->(b:Device) DELETE r"}
    if _WRITE_OTHER.search(ql):
        return {"intent": "write", "cypher": "MATCH (n:Device) SET n.modified = true RETURN n"}

    devices = devices or []
    nodes = _mentioned_devices(q, devices)
    ids = [n["id"] for n in nodes]

    if re.search(r"\bhow many\b|\bcount\b|\bnumber of\b", ql):
        if re.search(r"connection|link|route|edge", ql):
            return {"intent": "count_connections",
                    "cypher": "MATCH (:Device)-[r:CONNECTS_TO]->(:Device) RETURN count(r) AS connections"}
        return {"intent": "count_devices", "cypher": "MATCH (d:Device) RETURN count(d) AS devices"}

    if re.search(r"cve|vulnerab|exploit|unpatched", ql):
        if ids:
            return {"intent": "cves", "ids": ids,
                    "cypher": f"MATCH (d:Device) WHERE d.id IN {[i for i in ids]!r} "
                              "RETURN d.id AS id, d.name AS name, d.cves AS cves".replace('"', "'")}
        return {"intent": "cves", "ids": [],
                "cypher": "MATCH (d:Device) WHERE size(d.cves) > 0 RETURN d.id AS id, d.name AS name, d.cves AS cves"}

    port = re.search(r"\bport\s+(\d{1,5})\b|\b(\d{1,5})\s*/?\s*(?:tcp|udp)\b", ql)
    if port or (re.search(r"\bports?\b", ql) and not ids):
        if port:
            p = int(port.group(1) or port.group(2))
            return {"intent": "port", "port": p,
                    "cypher": f"MATCH (d:Device) WHERE {p} IN d.ports RETURN d.id AS id, d.name AS name, d.ports AS ports"}

    if ids and re.search(r"connect|neighbo|talk|reach|path|link|route|lateral|access|traffic|from|to\b|into|incoming|outgoing",
                         ql):
        nid = _esc(ids[0])
        if re.search(r"\bincoming\b|\binto\b|\b(?:who|which\s+\w+)\s+(?:can\s+)?(?:reach|access|talk)", ql):
            return {"intent": "connections", "node": ids[0], "direction": "in",
                    "cypher": f"MATCH (a:Device)-[r:CONNECTS_TO]->(b:Device {{id: '{nid}'}}) "
                              "RETURN a.id AS source, b.id AS target, r.type AS type"}
        if re.search(r"\boutgoing\b|\bfrom\b", ql):
            return {"intent": "connections", "node": ids[0], "direction": "out",
                    "cypher": f"MATCH (a:Device {{id: '{nid}'}})-[r:CONNECTS_TO]->(b:Device) "
                              "RETURN a.id AS source, b.id AS target, r.type AS type"}
        return {"intent": "connections", "node": ids[0], "direction": "both",
                "cypher": f"MATCH (a:Device)-[r:CONNECTS_TO]-(b:Device {{id: '{nid}'}}) "
                          "RETURN a.id AS source, b.id AS target, r.type AS type"}

    subnet = None
    if _PUBLIC.search(ql) and not _INTERNAL.search(ql):
        subnet = "public_dmz"
    elif _INTERNAL.search(ql) and not _PUBLIC.search(ql):
        subnet = "internal_core"
    if subnet and not ids:
        return {"intent": "subnet", "subnet": subnet,
                "cypher": f"MATCH (d:Device)-[:PART_OF_SUBNET]->(s:Subnet {{id: '{subnet}'}}) "
                          "RETURN d.id AS id, d.name AS name, d.ip AS ip"}

    if ids:
        return {"intent": "device", "ids": ids,
                "cypher": f"MATCH (d:Device) WHERE d.id IN {ids!r} "
                          "RETURN d.id AS id, d.name AS name, d.ip AS ip, d.os AS os, d.ports AS ports, d.cves AS cves"
                .replace('"', "'")}

    if re.search(r"connection|link|route|edge|topology|path", ql):
        return {"intent": "all_connections",
                "cypher": "MATCH (a:Device)-[r:CONNECTS_TO]->(b:Device) "
                          "RETURN a.id AS source, b.id AS target, r.type AS type"}
    if re.search(r"device|server|host|machine|workstation|node|asset|system|list|show|all|everything", ql):
        return {"intent": "all_devices",
                "cypher": "MATCH (d:Device) RETURN d.id AS id, d.name AS name, d.ip AS ip, d.os AS os"}

    raise ValueError(
        "Offline copilot could not understand that question. Try asking about devices, connections, "
        "subnets, CVEs, ports or a specific device id."
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
        return [{"id": d["id"], "name": d.get("name"), "ports": d.get("ports", [])}
                for d in devices if plan["port"] in (d.get("ports") or [])]
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
    if intent == "device":
        return [pick(by_id[i], "id", "name", "ip", "os", "ports", "cves") for i in plan["ids"] if i in by_id]
    if intent == "all_connections":
        return [{"source": c["source"], "target": c["target"], "type": c.get("type")} for c in conns]
    if intent == "all_devices":
        return [pick(d, "id", "name", "ip", "os") for d in devices]
    raise ValueError(f"Unsupported offline intent: {intent}")


def summarize_offline(question: str, plan: Optional[dict], records: list[dict[str, Any]]) -> str:
    """Plain-language summary built only from the returned records (never invents facts)."""
    if not records:
        return "Nothing in the current topology matched that question."
    intent = (plan or {}).get("intent", "")
    if intent.startswith("count_"):
        key, val = next(iter(records[0].items()))
        return f"There are {val} {key} in the current topology."
    if intent in ("connections", "all_connections"):
        pairs = [f"{r['source']} -> {r['target']}" for r in records[:8]]
        more = f" (+{len(records) - 8} more)" if len(records) > 8 else ""
        return f"Found {len(records)} connection(s): " + ", ".join(pairs) + more + "."
    if intent == "cves":
        parts = [f"{r['id']} ({', '.join(r['cves'])})" for r in records[:8] if r.get("cves")]
        return (f"{len(parts)} device(s) have known CVEs: " + ", ".join(parts) + ".") if parts \
            else "The matching devices have no recorded CVEs."
    if intent == "port":
        return f"{len(records)} device(s) expose port {plan['port']}: " + ", ".join(r["id"] for r in records[:10]) + "."
    names = [str(r.get("id") or r.get("name")) for r in records[:10]]
    more = f" (+{len(records) - 10} more)" if len(records) > 10 else ""
    return f"Found {len(records)} device(s): " + ", ".join(names) + more + "."
