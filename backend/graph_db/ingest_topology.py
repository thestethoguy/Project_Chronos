"""Reusable topology ingestion (Guide Section 7.3, Step 2).

Called by both the one-time seeding script (bottom of file) and POST /upload_topology.
Runs in ONE write transaction: if anything fails, the previous graph is left untouched
instead of being wiped and half-rebuilt.
"""
import importlib
import json
import os
import sys
from typing import Any

from backend.schemas.topology import NetworkTopologyFile


def _write(tx: Any, topology: NetworkTopologyFile) -> None:
    tx.run("MATCH (n) DETACH DELETE n")
    tx.run(
        "MERGE (:Subnet {id: 'public_dmz', scope: 'External Access'}) "
        "MERGE (:Subnet {id: 'internal_core', scope: 'Restricted Access'})"
    )
    tx.run(
        "UNWIND $devices AS d "
        "MATCH (s:Subnet {id: d.subnet}) "
        "MERGE (n:Device {id: d.id}) "
        "SET n.name = d.name, n.ip = d.ip, n.ports = d.ports, n.os = d.os, n.cves = d.cves "
        "MERGE (n)-[:PART_OF_SUBNET]->(s)",
        devices=[d.model_dump() for d in topology.devices],
    )
    tx.run(
        "UNWIND $conns AS c "
        "MATCH (a:Device {id: c.source}), (b:Device {id: c.target}) "
        "MERGE (a)-[:CONNECTS_TO {type: c.type}]->(b)",
        conns=[c.model_dump() for c in topology.connections],
    )


def ingest_topology(driver: Any, topology: NetworkTopologyFile) -> dict[str, int]:
    with driver.session() as session:
        session.execute_write(_write, topology)
    return {
        "deviceCount": len(topology.devices),
        "connectionCount": len(topology.connections),
    }


def read_topology(driver: Any) -> dict[str, list[dict[str, Any]]]:
    """Current graph in the NetworkTopologyFile shape the frontend expects."""
    with driver.session() as session:
        devices = [
            dict(r)
            for r in session.run(
                "MATCH (d:Device) "
                "OPTIONAL MATCH (d)-[:PART_OF_SUBNET]->(s:Subnet) "
                "RETURN d.id AS id, d.name AS name, d.ip AS ip, s.id AS subnet, "
                "d.ports AS ports, d.os AS os, coalesce(d.cves, []) AS cves "
                "ORDER BY d.id"
            )
        ]
        connections = [
            dict(r)
            for r in session.run(
                "MATCH (a:Device)-[r:CONNECTS_TO]->(b:Device) "
                "RETURN a.id AS source, b.id AS target, r.type AS type "
                "ORDER BY source, target"
            )
        ]
    return {"devices": devices, "connections": connections}


if __name__ == "__main__":  # python -m graph_db.ingest_topology sample_data/network_topology.json
    from backend.db.neo4j_driver import get_driver

    path = sys.argv[1] if len(sys.argv) > 1 else "sample_data/network_topology.json"
    with open(path, encoding="utf-8") as f:
        topo = NetworkTopologyFile(**json.load(f))
    drv = get_driver()
    if drv is None:
        _gdb: Any = importlib.import_module("neo4j").GraphDatabase
        uri: str = os.getenv("NEO4J_URI") or "bolt://localhost:7687"
        user: str = os.getenv("NEO4J_USER") or "neo4j"
        password: str = os.getenv("NEO4J_PASSWORD") or ""
        drv = _gdb.driver(uri, auth=(user, password))
    print(ingest_topology(drv, topo))
