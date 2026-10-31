"""Network topology access layer: optional Neo4j + always-available in-memory mirror.

The mirror is seeded from backend/graph_db/network_topology.json (Phase-1 `nodes`/`relationships`
format, converted to the Phase-2 `devices`/`connections` shape) and replaced by POST /upload_topology.
Every read prefers live Neo4j when reachable and non-empty, otherwise uses the mirror.
Every write (upload / cut_connection) updates the mirror and, when reachable, Neo4j too.

No pydantic import here on purpose; callers pass plain dicts.
"""
from __future__ import annotations

import copy
import json
import logging
import threading
from pathlib import Path
from typing import Any, Optional

from backend.db.neo4j_driver import get_driver

logger = logging.getLogger("chronos.topology")

DEFAULT_TOPOLOGY_PATH = Path(__file__).resolve().parents[1] / "graph_db" / "network_topology.json"
_SUBNET_MAP = {"subnet_public": "public_dmz", "subnet_secure": "internal_core"}

_lock = threading.RLock()
_mirror: Optional[dict] = None


def _convert_phase1(raw: dict) -> dict:
    """Phase-1 file ({nodes, relationships}) -> Phase-2 shape ({devices, connections})."""
    devices = []
    for n in raw.get("nodes", raw.get("devices", [])):
        d = dict(n)
        d["subnet"] = _SUBNET_MAP.get(d.get("subnet"), d.get("subnet"))
        d.setdefault("ports", [])
        d.setdefault("cves", [])
        devices.append(d)
    conns = [dict(c) for c in raw.get("relationships", raw.get("connections", []))]
    return {"devices": devices, "connections": conns}


def _load_default() -> dict:
    try:
        with open(DEFAULT_TOPOLOGY_PATH, encoding="utf-8") as f:
            return _convert_phase1(json.load(f))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not load default topology (%s); mirror starts empty.", exc)
        return {"devices": [], "connections": []}


def _ensure_mirror() -> dict:
    global _mirror
    with _lock:
        if _mirror is None:
            _mirror = _load_default()
        return _mirror


# ── mirror API ─────────────────────────────────────────────────────────────────────────────
def reset_mirror() -> None:
    """Re-seed the mirror from the bundled default topology."""
    global _mirror
    with _lock:
        _mirror = _load_default()


def get_mirror() -> dict:
    with _lock:
        return copy.deepcopy(_ensure_mirror())


def set_mirror(topology: dict) -> dict:
    global _mirror
    with _lock:
        _mirror = {
            "devices": copy.deepcopy(list(topology.get("devices", []))),
            "connections": copy.deepcopy(list(topology.get("connections", []))),
        }
        return {"deviceCount": len(_mirror["devices"]), "connectionCount": len(_mirror["connections"])}


def remove_mirror_connection(source: str, target: str) -> int:
    with _lock:
        m = _ensure_mirror()
        before = len(m["connections"])
        m["connections"] = [c for c in m["connections"] if not (c["source"] == source and c["target"] == target)]
        return before - len(m["connections"])


# ── Neo4j-aware API ────────────────────────────────────────────────────────────────────────
def _neo4j_read_topology() -> Optional[dict]:
    driver = get_driver()
    if driver is None:
        return None
    try:
        from backend.graph_db.ingest_topology import read_topology

        data = read_topology(driver)
        return data if data.get("devices") else None
    except Exception as exc:  # noqa: BLE001
        logger.warning("Neo4j read failed (%s); using mirror.", type(exc).__name__)
        return None


def get_topology() -> dict:
    """{"devices": [...], "connections": [...]} from Neo4j if reachable & populated, else the mirror."""
    live = _neo4j_read_topology()
    return live if live is not None else get_mirror()


def topology_source() -> str:
    return "neo4j" if _neo4j_read_topology() is not None else "mirror"


def store_topology(topology: dict) -> dict:
    """Persist an uploaded (already validated) topology to the mirror AND Neo4j when reachable."""
    counts = set_mirror(topology)
    neo4j_stored = False
    driver = get_driver()
    if driver is not None:
        try:
            from backend.schemas.topology import NetworkTopologyFile
            from backend.graph_db.ingest_topology import ingest_topology

            ingest_topology(driver, NetworkTopologyFile(**topology))
            neo4j_stored = True
        except Exception as exc:  # noqa: BLE001
            logger.warning("Neo4j ingest failed (%s); topology kept in mirror only.", type(exc).__name__)
    return {**counts, "storage": {"neo4j": neo4j_stored, "mirror": True}}


def load_demo_topology() -> dict:
    """Reload the bundled 20-node enterprise demo topology into the mirror (and Neo4j if reachable)."""
    default_topo = _load_default()
    return store_topology(default_topo)


def has_device(node_id: str) -> bool:
    return any(d["id"] == node_id for d in get_topology()["devices"])


def get_neighbors(node_id: str) -> tuple[list[str], str]:
    """Outbound CONNECTS_TO neighbours as (ids, source) where source is 'neo4j' or 'mirror'."""
    driver = get_driver()
    if driver is not None:
        try:
            with driver.session() as s:
                rows = s.run(
                    "MATCH (a:Device {id: $id})-[:CONNECTS_TO]->(b:Device) RETURN b.id AS n ORDER BY n",
                    id=node_id,
                )
                found = [r["n"] for r in rows]
            if found:
                return found, "neo4j"
        except Exception as exc:  # noqa: BLE001
            logger.warning("Neo4j neighbour query failed (%s); using mirror.", type(exc).__name__)
    seen, out = set(), []
    for c in get_mirror()["connections"]:
        if c["source"] == node_id and c["target"] not in seen:
            seen.add(c["target"])
            out.append(c["target"])
    return out, "mirror"


def cut_connection(source: str, target: str) -> dict:
    """Delete source->target in Neo4j (if reachable) and in the mirror."""
    neo4j_deleted: Optional[int] = None
    driver = get_driver()
    if driver is not None:
        try:
            with driver.session() as s:
                rec = s.run(
                    "MATCH (a:Device {id: $s})-[r:CONNECTS_TO]->(b:Device {id: $t}) "
                    "DELETE r RETURN count(r) AS n",
                    s=source, t=target,
                ).single()
                neo4j_deleted = int(rec["n"]) if rec else 0
        except Exception as exc:  # noqa: BLE001
            logger.warning("Neo4j cut failed (%s); mirror still updated.", type(exc).__name__)
    mirror_deleted = remove_mirror_connection(source, target)
    return {
        "source": source,
        "target": target,
        "neo4j_deleted": neo4j_deleted,  # None => Neo4j not used
        "mirror_deleted": mirror_deleted,
        "severed": bool(mirror_deleted or neo4j_deleted),
    }
