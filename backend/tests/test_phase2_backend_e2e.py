"""Phase 2 backend end-to-end tests (HITL gate, topology, copilot). Fully offline:
in-memory Mongo, no Neo4j, no Groq -> deterministic tool pipeline + offline copilot."""
import json
import os
from pathlib import Path

# Force offline mode BEFORE importing the app (empty strings stop load_dotenv from re-populating them).
for _k in ("MONGODB_URI", "NEO4J_URI", "NEO4J_PASSWORD", "NEO4J_USER", "GROQ_API_KEY"):
    os.environ[_k] = ""
os.environ["CHRONOS_FORCE_DETERMINISTIC"] = "true"
os.environ["CHRONOS_USE_MOCK_AWS"] = "true"

import pytest
from fastapi.testclient import TestClient

from backend import main as main_mod
from backend.db import mongo, session_store, topology_store
from backend.db.neo4j_driver import reset_driver_cache

import orchestrator as orch  # same module object that backend.main uses

SAMPLE = Path(__file__).resolve().parents[2] / "sample_data" / "network_topology.json"


@pytest.fixture(autouse=True)
def clean_state(tmp_path, monkeypatch):
    reset_driver_cache()
    session_store.set_collection_factory(mongo.sessions_collection)  # undo other tests' injected collection
    mongo.sessions_collection().delete_many({})
    topology_store.reset_mirror()
    monkeypatch.setattr(orch._defense_logger, "log_file", tmp_path / "audit.log")
    yield


@pytest.fixture
def client():
    return TestClient(main_mod.app)


def _upload(client, name, content, ctype="application/json"):
    return client.post("/upload_topology", files={"topology_file": (name, content, ctype)})


def _edge_exists(client, src, tgt) -> bool:
    return any(c["source"] == src and c["target"] == tgt for c in client.get("/topology").json()["connections"])


def _audit_text() -> str:
    p = orch.get_audit_log_path()
    return p.read_text(encoding="utf-8") if p.exists() else ""


# ── 1. topology upload / read ───────────────────────────────────────────────────────────────
def test_default_topology_served_from_mirror(client):
    topo = client.get("/topology").json()
    ids = {d["id"] for d in topo["devices"]}
    assert {"proxy_ingress", "auth_controller", "db_secret_01"} <= ids
    assert {d["subnet"] for d in topo["devices"]} <= {"public_dmz", "internal_core"}
    assert any(c["source"] == "web_server_01" and c["target"] == "auth_controller" for c in topo["connections"])


def test_upload_valid_topology_then_get(client):
    r = _upload(client, "network_topology.json", SAMPLE.read_bytes())
    assert r.status_code == 200, r.text
    assert r.json()["deviceCount"] == 6 and r.json()["connectionCount"] == 5
    topo = client.get("/topology").json()
    assert {d["id"] for d in topo["devices"]} == {"web-01", "vpn-gw", "auth-ctl", "dc-01", "wks-17", "sql-classified"}
    assert len(topo["connections"]) == 5


def test_upload_rejects_txt_with_400(client):
    assert _upload(client, "topology.txt", b"{}", "text/plain").status_code == 400


def test_upload_rejects_invalid_json_with_400(client):
    assert _upload(client, "topology.json", b"{not json").status_code == 400


def test_upload_rejects_unknown_device_id_with_422(client):
    bad = json.loads(SAMPLE.read_text())
    bad["connections"].append({"source": "web-01", "target": "ghost-99", "type": "X"})
    r = _upload(client, "topology.json", json.dumps(bad).encode())
    assert r.status_code == 422
    assert "unknown device id" in r.json()["detail"]
    assert "web-01" not in {d["id"] for d in client.get("/topology").json()["devices"]}  # mirror untouched


def test_upload_rejects_non_object_with_422(client):
    assert _upload(client, "topology.json", b"[1,2,3]").status_code == 422


# ── 2. start_simulation -> awaiting_approval ────────────────────────────────────────────────
def test_start_simulation_produces_pending_proposal_and_blocks_second_start(client, monkeypatch):
    calls, real = [], main_mod.update_current_session
    monkeypatch.setattr(main_mod, "update_current_session", lambda **f: (calls.append(f), real(**f))[1])

    assert client.get("/simulation_status").json()["status"] == "idle"
    r = client.post("/start_simulation")
    assert r.status_code == 202 and r.json()["status"] == "running"

    statuses = [c["status"] for c in calls if "status" in c]
    assert statuses == ["awaiting_approval"]  # worker parked the session for the human
    assert "Red Agent active" in calls[0]["latest_event"]  # progress update preceded the proposal

    s = client.get("/simulation_status").json()
    assert s["status"] == "awaiting_approval" and s["cycles_run"] == 1
    assert s["compromised_node"] == "auth_controller"
    assert s["mitre_tactic"].startswith("Lateral Movement") and "T1550.002" in s["mitre_tactic"]
    assert isinstance(s["anomaly_score"], float) and 0.0 <= s["anomaly_score"] <= 1.0
    assert s["red_report"] and s["blue_report"]

    pa = s["pending_action"]
    assert (pa["source"], pa["target"]) == ("web_server_01", "auth_controller")
    assert pa["anomaly_score"] == s["anomaly_score"]
    assert "Pass-the-hash" in pa["cited_incident"] or "Reverse Proxy" in pa["cited_incident"]
    assert pa["cited_incident"] in s["blue_report"] and f"{pa['anomaly_score']:.4f}" in s["blue_report"]
    assert pa["aws_remediation"]["executed"] is False
    assert pa["aws_remediation"].get("data_source") in ("aws", "mock")
    assert pa["justification"] and pa["proposed_at"]

    r2 = client.post("/start_simulation")
    assert r2.status_code == 409
    assert client.post("/reset_simulation").status_code == 200  # allowed while awaiting_approval


def test_blue_agent_has_bounded_authority():
    blue = {getattr(t, "name", None) for t in orch.BLUE_AGENT_TOOLS}
    assert blue == {"ml_score_anomaly", "rag_retrieve_incidents", "draft_iam_policy_diff", "draft_ec2_isolation_plan"}
    assert {getattr(t, "name", None) for t in orch.RED_AGENT_TOOLS} == {"graph_scan_neighbors"}
    assert callable(orch.perform_graph_cut) and callable(orch.write_audit_entry)  # still importable for HITL
    assert orch.graph_cut_connection is not None and orch.audit_log_action is not None


def test_simulation_on_uploaded_topology_proposes_valid_edge(client):
    assert _upload(client, "t.json", SAMPLE.read_bytes()).status_code == 200
    assert client.post("/start_simulation").status_code == 202
    pa = client.get("/simulation_status").json()["pending_action"]
    assert _edge_exists(client, pa["source"], pa["target"])


# ── 3. approve ──────────────────────────────────────────────────────────────────────────────
def test_approve_severs_edge_audits_and_completes(client):
    client.post("/start_simulation")
    pa = client.get("/simulation_status").json()["pending_action"]
    assert _edge_exists(client, pa["source"], pa["target"])

    r = client.post("/approve_action")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "completed"
    assert body["action_taken"] == f"Severed {pa['source']} -> {pa['target']} (Approved by human-analyst)"

    assert not _edge_exists(client, pa["source"], pa["target"])  # GET /topology reflects the cut immediately
    log = _audit_text()
    assert "CONNECTION_SEVERED" in log and "human-analyst" in log and pa["target"] in log

    s = client.get("/simulation_status").json()
    assert s["status"] == "completed" and s["pending_action"] is None
    assert client.post("/approve_action").status_code == 409  # cannot approve twice
    assert client.post("/reject_action").status_code == 409


def test_approve_and_reject_without_pending_return_409(client):
    assert client.post("/approve_action").status_code == 409
    assert client.post("/reject_action").status_code == 409


# ── 4. reject (second cycle) ────────────────────────────────────────────────────────────────
def test_reject_on_second_cycle_keeps_edge_and_audits(client):
    client.post("/start_simulation")
    client.post("/approve_action")  # cycle 1 approved
    assert client.post("/start_simulation").status_code == 202  # cycle 2 allowed after completion
    s = client.get("/simulation_status").json()
    assert s["status"] == "awaiting_approval" and s["cycles_run"] == 2
    pa = s["pending_action"]
    assert _edge_exists(client, pa["source"], pa["target"])

    r = client.post("/reject_action")
    assert r.status_code == 200
    assert r.json() == {"status": "completed", "action_taken": "No action taken (proposal rejected by analyst)."}
    assert _edge_exists(client, pa["source"], pa["target"])  # graph untouched

    log = _audit_text()
    assert "PROPOSAL_REJECTED" in log and log.count("human-analyst") >= 2
    s = client.get("/simulation_status").json()
    assert s["status"] == "completed" and s["pending_action"] is None


def test_reset_preserves_cycles_and_audit_logs_endpoint(client):
    client.post("/start_simulation")
    client.post("/reject_action")
    assert client.post("/reset_simulation").json()["status"] == "idle"
    s = client.get("/simulation_status").json()
    assert s["status"] == "idle" and s["cycles_run"] == 1
    entries = client.get("/audit_logs").json()
    assert entries["count"] == 1
    e = entries["entries"][0]
    assert e["action"] == "PROPOSAL_REJECTED" and e["approved_by"] == "human-analyst" and e["anomaly_score"] is not None


def test_health_check(client):
    h = client.get("/").json()
    assert h["version"] == "2.0.0"
    assert h["orchestrator"]["loaded"] is True and h["orchestrator"]["mode"] == "deterministic"
    assert h["database"] == {"type": "in-memory", "status": "fallback"}
    assert h["simulation_status"] == "idle" and h["neo4j"] == "not_configured"


def test_defense_logger_backward_compatible(tmp_path):
    from backend.ml_engine.defense_logger import DefenseLogger

    lg = DefenseLogger(str(tmp_path / "a.log"))
    lg.log_action("n1", "isolated", 0.5, "why", "Lateral Movement")  # Phase-1 call style
    lg.log_action("n2", "blocked", 0.7, "why")  # Phase-1 default tactic
    lg.log_action("n3", "x", 0.1, "why", approved_by="human-analyst")
    lines = (tmp_path / "a.log").read_text().splitlines()
    assert "APPROVED BY: autonomous-soar" in lines[0] and "Initial Access" in lines[1]
    assert "APPROVED BY: human-analyst" in lines[2]


# ── 5. SOC Copilot ──────────────────────────────────────────────────────────────────────────
def test_copilot_answers_read_only_question_offline(client):
    r = client.post("/copilot/ask", json={"question": "Which devices are in the internal subnet?"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["cypher_query"].upper().startswith("MATCH") and "LIMIT" in body["cypher_query"].upper()
    assert body["mode"] == "offline" and body["data_source"] == "mirror"
    ids = {row["id"] for row in body["raw_result"]}
    assert "auth_controller" in ids and "web_server_01" not in ids
    assert "auth_controller" in body["answer"]


def test_copilot_connections_and_cves_reflect_live_mirror(client):
    q = "What connections does web_server_01 have?"
    before = client.post("/copilot/ask", json={"question": q}).json()["raw_result"]
    assert any(r["target"] == "auth_controller" for r in before)
    client.post("/start_simulation")
    client.post("/approve_action")  # severs web_server_01 -> auth_controller
    after = client.post("/copilot/ask", json={"question": q}).json()["raw_result"]
    assert not any(r["source"] == "web_server_01" and r["target"] == "auth_controller" for r in after)
    cves = client.post("/copilot/ask", json={"question": "Which devices have known CVEs?"}).json()
    assert cves["raw_result"] and all(r["cves"] for r in cves["raw_result"])


@pytest.mark.parametrize("question", [
    "DELETE all connections in the network",
    "Please remove the link between web_server_01 and auth_controller",
    "create a new device called evil",
])
def test_copilot_blocks_destructive_requests_with_422(client, question):
    r = client.post("/copilot/ask", json={"question": question})
    assert r.status_code == 422, r.text
    assert client.get("/topology").json()["connections"]  # nothing was modified


def test_copilot_empty_question_400_and_gibberish_422(client):
    assert client.post("/copilot/ask", json={"question": "   "}).status_code == 400
    assert client.post("/copilot/ask", json={}).status_code == 400
    assert client.post("/copilot/ask", json={"question": "qwerty zxcvb"}).status_code == 422


def test_validator_forbidden_keywords():
    from backend.copilot.nl_to_cypher import FORBIDDEN_KEYWORDS, validate_cypher

    for kw in ("CREATE", "MERGE", "DELETE", "SET", "REMOVE", "DROP", "CALL"):
        assert FORBIDDEN_KEYWORDS.search(f"MATCH (n) {kw} x")
        with pytest.raises(ValueError):
            validate_cypher(f"MATCH (n) {kw} n RETURN n")
    assert validate_cypher("MATCH (d:Device) RETURN d.id").endswith("LIMIT 50")
