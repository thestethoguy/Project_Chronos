import importlib
import os
from pathlib import Path
from typing import Any

try:
    _dotenv: Any = importlib.import_module("dotenv")
    _dotenv.load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")
except Exception:  # noqa: BLE001
    pass

URI: str = os.getenv("NEO4J_URI") or "bolt://localhost:7687"
USER: str = os.getenv("NEO4J_USER") or "neo4j"
PASSWORD: str = os.getenv("NEO4J_PASSWORD") or ""


def _graph_database() -> Any:
    return importlib.import_module("neo4j").GraphDatabase


# Core Helper Function to execute read operations safely
def execute_read_query(query: str, parameters: dict[str, Any] | None = None) -> list[Any]:
    driver = _graph_database().driver(URI, auth=(USER, PASSWORD))
    with driver.session() as session:
        result = session.run(query, parameters)
        # Extract records out of the database driver stream format
        data = [record for record in result]
    driver.close()
    return data


# Core Helper Function to execute modification operations safely
def execute_write_query(query: str, parameters: dict[str, Any] | None = None) -> None:
    driver = _graph_database().driver(URI, auth=(USER, PASSWORD))
    with driver.session() as session:
        session.run(query, parameters)
    driver.close()


# STEP 1: Give the AI glasses to scan adjacent pathways
def get_neighbors(node_id: str) -> list[str]:
    """
    Finds all device IDs directly connected to the target node.
    """
    cypher_query = """
    MATCH (a:Device {id: $target_id})-[:CONNECTS_TO]->(b:Device)
    RETURN b.id AS neighbor_id
    """
    records = execute_read_query(cypher_query, {"target_id": node_id})

    # Extract just the ID strings out of the returned table rows
    neighbors_list = [str(row["neighbor_id"]) for row in records]
    return neighbors_list


# STEP 2: The Blue Agent SOAR action - Cutting network cables
def cut_connection(source_id: str, target_id: str) -> None:
    """
    Deletes the specific connection line between two nodes, isolating threats.
    """
    cypher_query = """
    MATCH (src:Device {id: $src_id})-[r:CONNECTS_TO]->(tgt:Device {id: $tgt_id})
    DELETE r
    """
    execute_write_query(cypher_query, {"src_id": source_id, "tgt_id": target_id})
    print(f"--- SOAR ALERT: Severed network route from {source_id} -> {target_id}! ---")


if __name__ == "__main__":
    print("==================================================")
    print("PHASE 3 DIAGNOSTIC: SIMULATING SOAR INTERVENTION")
    print("==================================================")

    # 1. Scan initial pathways for our ingress proxy server
    print("\n[Step 1] Scanning pathways for 'proxy_ingress'...")
    initial_routes = get_neighbors("proxy_ingress")
    print("Active Outbound Routes Discovered:", initial_routes)

    # 2. Simulate the Blue Agent detecting an attack and severing the link to web_server_01
    print("\n[Step 2] Blue Agent triggers SOAR response! Severing web_server_01...")
    cut_connection("proxy_ingress", "web_server_01")

    # 3. Re-verify neighbors to prove the path is dead
    print("\n[Step 3] Re-scanning pathways for 'proxy_ingress'...")
    post_remediation_routes = get_neighbors("proxy_ingress")
    print("Remaining Active Routes:", post_remediation_routes)
    print("==================================================")
