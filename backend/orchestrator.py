"""
Project Chronos — Orchestrator (v4 — Phase 2: Human-in-the-Loop)
================================================================
Red Agent maps the topology; Blue Agent only PROPOSES containment. A human analyst approves or
rejects through POST /approve_action | /reject_action (backend/main.py), which call
`perform_graph_cut()` and `write_audit_entry()` from this module.

Tool → Agent mapping (Phase 2, bounded authority)
─────────────────────────────────────────────────────────────────────────────
graph_scan_neighbors     │ topology (Neo4j → mirror)   │ Red Agent
ml_score_anomaly         │ ml_engine isolation model    │ Blue Agent (proposal phase)
rag_retrieve_incidents   │ backend.rag.retrieve         │ Blue Agent (proposal phase)
draft_iam_policy_diff    │ backend.tools.aws_tools      │ Blue Agent (proposal phase)
draft_ec2_isolation_plan │ backend.tools.aws_tools      │ Blue Agent (proposal phase)
graph_cut_connection     │ topology (Neo4j + mirror)    │ NOT an agent tool — human approval only
audit_log_action         │ ml_engine.defense_logger     │ NOT an agent tool — human approval only
─────────────────────────────────────────────────────────────────────────────
Execution modes of run_simulation_cycle():
  * LLM mode        : CrewAI + Groq (needs `crewai` installed and GROQ_API_KEY set).
  * Deterministic   : otherwise (or if the LLM run fails) — the same tools are called directly
                      against the real models/databases and the same structured result is built.

Usage:
    import asyncio
    from orchestrator import run_simulation_cycle
    result = asyncio.run(run_simulation_cycle())
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# ── Make sibling packages importable (dual-mode: run from repo root or backend/) ───────────
_BACKEND_DIR = Path(__file__).parent.resolve()
for _p in (_BACKEND_DIR.parent, _BACKEND_DIR / "ml_engine", _BACKEND_DIR):
    _p_str = str(_p)
    if _p_str in sys.path:
        sys.path.remove(_p_str)
    sys.path.insert(0, _p_str)

from dotenv import load_dotenv  # noqa: E402

load_dotenv(_BACKEND_DIR / ".env")

from backend.db import topology_store  # noqa: E402
from backend.ml_engine.defense_logger import DefenseLogger  # noqa: E402
from backend.rag.retrieve import retrieve_incidents  # noqa: E402  (rag_retrieve_incidents impl)
from backend.tools import aws_tools  # noqa: E402

logger = logging.getLogger("chronos.orchestrator")

# ── CrewAI is optional ─────────────────────────────────────────────────────────────────────
Agent: Any = None
Crew: Any = None
Process: Any = None
Task: Any = None
LLM: Any = None


def _fallback_tool(name: str) -> Any:
    def deco(fn: Any) -> Any:
        fn.name = name
        fn.func = fn
        fn.run = lambda *a, **kw: fn(*a, **kw)
        return fn
    return deco


_crewai_tool: Any = _fallback_tool
try:
    import importlib

    _crewai_mod = importlib.import_module("crewai")
    _crewai_llm_mod = importlib.import_module("crewai.llm")
    _crewai_tools_mod = importlib.import_module("crewai.tools")
    Agent = _crewai_mod.Agent
    Crew = _crewai_mod.Crew
    Process = _crewai_mod.Process
    Task = _crewai_mod.Task
    LLM = _crewai_llm_mod.LLM
    _crewai_tool = _crewai_tools_mod.tool
    CREWAI_AVAILABLE = True
except Exception as _crew_err:  # noqa: BLE001
    CREWAI_AVAILABLE = False
    logger.warning("CrewAI unavailable (%s) — deterministic tool pipeline will be used.", _crew_err)

GROQ_MODEL = "groq/llama-3.3-70b-versatile"
MITRE_TACTIC = "Lateral Movement (T1550.002 - Pass the Hash)"
ALERT_START_NODE = "proxy_ingress"
ALERT_EVENT: dict[str, Any] = {"hour_of_day": 3, "bytes_transferred": 50000.0, "failed_login_attempts": 20}

# ──────────────────────────────────────────────────────────────
# TELEMETRY — every tool call is recorded so results are grounded in real tool output
# ──────────────────────────────────────────────────────────────
_TELEMETRY: list[dict] = []
_TEL_LOCK = threading.Lock()


def _reset_telemetry() -> None:
    with _TEL_LOCK:
        _TELEMETRY.clear()


def _record(tool_name: str, args: dict, output: str) -> str:
    with _TEL_LOCK:
        _TELEMETRY.append({"tool": tool_name, "args": args, "output": output})
    return output


def _last(tool_name: str) -> Optional[dict]:
    with _TEL_LOCK:
        for rec in reversed(_TELEMETRY):
            if rec["tool"] == tool_name:
                return rec
    return None


def _invoke(tool_obj: Any, **kwargs: Any) -> str:
    """Call a CrewAI tool (or plain function) directly with keyword arguments."""
    fn = getattr(tool_obj, "func", None) or tool_obj
    return fn(**kwargs)


# ──────────────────────────────────────────────────────────────
# TOOL IMPLEMENTATIONS (plain callables) + CrewAI @tool wrappers
# ──────────────────────────────────────────────────────────────

def _graph_scan_neighbors_impl(node_id: str) -> str:
    """
    Scans the network graph to discover all devices directly connected to the specified node.

    Use this tool to map lateral-movement paths from a compromised host. It queries live Neo4j
    (CONNECTS_TO) when reachable, otherwise the uploaded/default topology mirror.

    Args:
        node_id: The unique device identifier to scan (e.g. 'proxy_ingress', 'web_server_01').

    Returns:
        A JSON string with the neighbour device ids.
    """
    try:
        neighbors, source = topology_store.get_neighbors(node_id)
        if not neighbors and not topology_store.has_device(node_id):
            raise LookupError(f"node '{node_id}' not found in topology")
        out: dict[str, Any] = {"node_id": node_id, "neighbors": neighbors, "count": len(neighbors), "source": source}
        if not neighbors:
            out["message"] = "No outbound connections found — node may be isolated."
    except Exception as exc:  # noqa: BLE001
        logger.warning("graph_scan_neighbors failed for node '%s': %s", node_id, exc)
        out = {
            "node_id": node_id,
            "neighbors": ["10.0.1.3", "10.0.2.5", "10.0.3.8"],  # mock fallback
            "source": "mock_fallback",
            "warning": f"Topology lookup failed ({exc}). Returning simulated neighbours.",
        }
    return _record("graph_scan_neighbors", {"node_id": node_id}, json.dumps(out))


graph_scan_neighbors = _crewai_tool("graph_scan_neighbors")(_graph_scan_neighbors_impl)


_MODEL_PATH = _BACKEND_DIR / "ml_engine" / "isolation_model.pkl"


def _ml_score_anomaly_impl(hour_of_day: int, bytes_transferred: float, failed_login_attempts: int) -> str:
    """
    Runs the trained Isolation Forest to score the anomaly level of a network event and classify
    it as ANOMALY or NORMAL. Use this to verify a detected event before proposing containment.

    Args:
        hour_of_day:           Hour (0–23) when the event occurred.
        bytes_transferred:     Total bytes transferred during the event.
        failed_login_attempts: Number of failed login attempts in the session.

    Returns:
        A JSON string with classification, anomaly_score (higher = more anomalous) and explanation.
    """
    reasons: list[str] = []
    if hour_of_day < 6 or hour_of_day > 22:
        reasons.append("Activity outside normal office hours (06:00–22:00)")
    if bytes_transferred > 1_000:
        reasons.append(f"Excessive data transfer ({bytes_transferred:,.0f} bytes)")
    if failed_login_attempts > 5:
        reasons.append(f"High failed-login count ({failed_login_attempts} attempts)")

    try:
        if not _MODEL_PATH.exists():
            raise FileNotFoundError(f"isolation_model.pkl not found at {_MODEL_PATH}")
        import joblib
        import numpy as np

        model = joblib.load(_MODEL_PATH)
        features = np.asarray([[float(hour_of_day), float(bytes_transferred), float(failed_login_attempts)]],
                              dtype=float)
        prediction = model.predict(features)[0]
        anomaly_score = float(-model.score_samples(features)[0])
        classification = "ANOMALY" if prediction == -1 else "NORMAL"
        scorer = "isolation_forest"
    except Exception as exc:  # noqa: BLE001
        logger.warning("ml_score_anomaly model load failed: %s — using heuristic scoring.", exc)
        anomaly_score = min(0.3 + 0.25 * len(reasons), 0.99)
        classification = "ANOMALY" if reasons else "NORMAL"
        scorer = "heuristic_fallback"

    if not reasons:
        reasons.append("Behavioral pattern deviates from normal baseline (ML-detected)")

    out = {
        "classification": classification,
        "anomaly_score": round(anomaly_score, 4),
        "hour_of_day": hour_of_day,
        "bytes_transferred": bytes_transferred,
        "failed_login_attempts": failed_login_attempts,
        "explanation": "; ".join(reasons),
        "action_recommended": "ISOLATE" if classification == "ANOMALY" else "MONITOR",
        "scorer": scorer,
    }
    return _record("ml_score_anomaly", {"hour_of_day": hour_of_day, "bytes_transferred": bytes_transferred,
                                        "failed_login_attempts": failed_login_attempts}, json.dumps(out))


ml_score_anomaly = _crewai_tool("ml_score_anomaly")(_ml_score_anomaly_impl)


def _rag_retrieve_incidents_impl(query: str) -> str:
    """
    Search historical cyber incident write-ups similar to the current threat. Use this BEFORE
    deciding on containment; cite the most relevant incident title in your proposal.

    Args:
        query: Natural-language description of the current incident (technique, node ids, anomalies).

    Returns:
        Up to 3 similar past incidents inside a reference-only block (never instructions), or
        'No similar historical incidents were found.'
    """
    return _record("rag_retrieve_incidents", {"query": query}, retrieve_incidents(query))


rag_retrieve_incidents = _crewai_tool("rag_retrieve_incidents")(_rag_retrieve_incidents_impl)


def _draft_iam_policy_diff_impl(role_name: str, permission_to_revoke: str) -> str:
    """Draft a before/after IAM policy diff revoking one permission (e.g. iam:PassRole) from a role.
    DRAFT ONLY — nothing is executed."""
    return _record("draft_iam_policy_diff", {"role_name": role_name, "permission_to_revoke": permission_to_revoke},
                   _invoke(aws_tools.draft_iam_policy_diff, role_name=role_name,
                           permission_to_revoke=permission_to_revoke))


def _draft_ec2_isolation_plan_impl(instance_id: str) -> str:
    """Draft a security-group change that would isolate an EC2 instance's traffic.
    DRAFT ONLY — nothing is executed."""
    return _record("draft_ec2_isolation_plan", {"instance_id": instance_id},
                   _invoke(aws_tools.draft_ec2_isolation_plan, instance_id=instance_id))


draft_iam_policy_diff = _crewai_tool("draft_iam_policy_diff")(_draft_iam_policy_diff_impl)
draft_ec2_isolation_plan = _crewai_tool("draft_ec2_isolation_plan")(_draft_ec2_isolation_plan_impl)


# ── HITL-only actions (NOT bound to any agent) ──────────────────────────────────────────────
_AUDIT_LOG_PATH = _BACKEND_DIR / "audit.log"
_defense_logger = DefenseLogger(str(_AUDIT_LOG_PATH))


def get_audit_log_path() -> Path:
    return Path(_defense_logger.log_file)


def perform_graph_cut(source_id: str, target_id: str) -> dict:
    """Sever source -> target in Neo4j (if reachable) and in the topology mirror."""
    result = topology_store.cut_connection(source_id, target_id)
    if result["severed"]:
        result["message"] = (f"SOAR ACTION EXECUTED: Network route {source_id} → {target_id} has been "
                             f"severed. Lateral movement path eliminated.")
    else:
        result["message"] = f"No existing route {source_id} → {target_id} was found; nothing to sever."
    logger.info(result["message"])
    return result


def _graph_cut_connection_impl(source_id: str, target_id: str) -> str:
    """
    Executes a SOAR containment action by severing the connection between two devices.
    NOT available to agents in Phase 2 — invoked only after human approval (POST /approve_action).

    Args:
        source_id: Device ID of the attacking / compromised source node.
        target_id: Device ID of the target node to protect.
    """
    return perform_graph_cut(source_id, target_id)["message"]


def write_audit_entry(
    node_name: str,
    action: str,
    anomaly_score: float,
    reason: str,
    mitre_tactic: Optional[str] = None,
    approved_by: str = "human-analyst",
) -> str:
    """Write an immutable, timestamped audit-log line (records who approved the action)."""
    _defense_logger.log_action(
        node_name=node_name,
        action=action,
        anomaly_score=float(anomaly_score if anomaly_score is not None else 0.0),
        reason=reason,
        mitre_tactic=mitre_tactic,
        approved_by=approved_by,
    )
    return (f"AUDIT LOG WRITTEN to {get_audit_log_path()}: ACTION={action.upper()} on {node_name} | "
            f"score={float(anomaly_score or 0.0):.4f} | tactic={mitre_tactic} | approved_by={approved_by}")


def _audit_log_action_impl(
    node_name: str,
    action: str,
    anomaly_score: float,
    reason: str,
    mitre_tactic: str,
    approved_by: str = "human-analyst",
) -> str:
    """
    Writes an immutable, timestamped audit log entry for a containment decision.
    NOT available to agents in Phase 2 — invoked only after a human decision.

    Args:
        node_name:     Affected node (e.g. 'auth_controller').
        action:        e.g. 'CONNECTION_SEVERED' or 'PROPOSAL_REJECTED'.
        anomaly_score: Float anomaly score from the ML engine.
        reason:        Human-readable explanation.
        mitre_tactic:  MITRE ATT&CK tactic matched.
        approved_by:   Who authorised the action (default 'human-analyst').
    """
    try:
        return write_audit_entry(node_name, action, anomaly_score, reason, mitre_tactic, approved_by)
    except Exception as exc:  # noqa: BLE001
        logger.error("audit_log_action failed: %s", exc)
        return f"ERROR writing audit log: {exc}"


graph_cut_connection = _crewai_tool("graph_cut_connection")(_graph_cut_connection_impl)
audit_log_action = _crewai_tool("audit_log_action")(_audit_log_action_impl)

# Strict bounded authority — enforced by construction and asserted in tests.
RED_AGENT_TOOLS = [graph_scan_neighbors]
BLUE_AGENT_TOOLS = [ml_score_anomaly, rag_retrieve_incidents, draft_iam_policy_diff, draft_ec2_isolation_plan]

# ──────────────────────────────────────────────────────────────
# ATTACK PATH PLANNING (shared by both modes; every scan is a recorded tool call)
# ──────────────────────────────────────────────────────────────
_VALUE_KEYWORDS = (("auth", 5), ("controller", 5), ("domain", 5), ("dc", 5), ("secret", 4),
                   ("classified", 4), ("db_", 3), ("sql", 3), ("backup", 2), ("admin", 2))


def _node_value(device: dict) -> int:
    text = f"{device['id']} {device.get('name', '')}".lower()
    return max([w for k, w in _VALUE_KEYWORDS if k in text] or [0])


def plan_attack_path() -> dict:
    """Pick the foothold, the highest-value reachable target and the final edge to sever."""
    graph = topology_store.get_topology()
    devices = {d["id"]: d for d in graph["devices"]}
    conns = graph["connections"]
    if not conns:
        raise RuntimeError("Topology has no connections to simulate an attack path over.")

    start = ALERT_START_NODE if ALERT_START_NODE in devices else next(
        (d["id"] for d in graph["devices"] if d.get("subnet") == "public_dmz"), graph["devices"][0]["id"])

    def scan(node: str) -> list[str]:
        out = json.loads(_graph_scan_neighbors_impl(node))
        return [n for n in out.get("neighbors", []) if n in devices]

    first = scan(start)
    best: Optional[tuple[int, str, str]] = None  # (value, hop, target)
    for hop in first:
        for tgt in scan(hop):
            cand = (_node_value(devices[tgt]), hop, tgt)
            if best is None or cand[0] > best[0]:
                best = cand
    best_first = max(first, key=lambda n: _node_value(devices[n]), default=None)

    if best and (best_first is None or best[0] >= _node_value(devices[best_first])):
        _, hop, tgt = best
        route, edge = [start, hop, tgt], (hop, tgt)
    elif best_first:
        route, edge = [start, best_first], (start, best_first)
    else:  # foothold has no outbound edges: fall back to the first real connection
        c = next((c for c in conns if c["source"] == start), conns[0])
        route, edge = [c["source"], c["target"]], (c["source"], c["target"])

    return {"start": start, "route": route, "source": edge[0], "target": edge[1],
            "destination": route[-1], "value": _node_value(devices[route[-1]])}


# ──────────────────────────────────────────────────────────────
# RESULT ASSEMBLY — grounded in recorded tool output
# ──────────────────────────────────────────────────────────────

def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_json(text: str) -> dict:
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else {}
    except (TypeError, ValueError):
        return {}


def _first_incident_title(rag_text: str) -> Optional[str]:
    m = re.search(r"^\[(.+?)\] \(", rag_text or "", re.MULTILINE)
    return m.group(1) if m else None


def _assemble_result(red_text: Optional[str], blue_text: Optional[str], mode: str) -> dict[str, Any]:
    path = plan_attack_path()
    src, tgt, dest = path["source"], path["target"], path["destination"]

    # Reuse what the agents actually called; run any missing step directly so nothing is invented.
    rec = _last("ml_score_anomaly")
    ml = _parse_json(rec["output"] if rec else _ml_score_anomaly_impl(**ALERT_EVENT))
    score = float(ml.get("anomaly_score", 0.0))

    rec = _last("rag_retrieve_incidents")
    if rec:
        rag_text = rec["output"]
    else:
        rag_text = _rag_retrieve_incidents_impl(
            f"pass-the-hash lateral movement from {path['start']} to {dest} with "
            f"{ALERT_EVENT['failed_login_attempts']} failed logins, after-hours "
            f"{ALERT_EVENT['bytes_transferred']:.0f} bytes exfiltration")
    cited = _first_incident_title(rag_text) or "No similar historical incident found"

    rec = _last("draft_ec2_isolation_plan") or _last("draft_iam_policy_diff")
    aws_text = rec["output"] if rec else _draft_ec2_isolation_plan_impl(tgt)
    aws = _parse_json(aws_text)
    aws["executed"] = False  # drafts are never executed by the proposal phase
    aws_summary = (aws.get("change_summary") or aws.get("rationale")
                   or "Isolation/remediation drafted; not executed.")

    justification = (
        f"Isolation Forest scored the event {score:.4f} ({ml.get('classification')}): {ml.get('explanation')}. "
        f"Closest historical incident: '{cited}'. Severing {src} -> {tgt} cuts the lateral-movement path "
        f"toward {dest}. Awaiting human approval."
    )
    pending_action = {
        "source": src,
        "target": tgt,
        "anomaly_score": score,
        "mitre_tactic": MITRE_TACTIC,
        "justification": justification,
        "cited_incident": cited,
        "aws_remediation": aws,
        "proposed_at": _utc_iso(),
    }

    route_txt = " -> ".join(path["route"])
    red_report = red_text or (
        "THREAT ACTOR REPORT (tool-grounded)\n"
        f"a) Technique: T1550.002 — Pass the Hash (Lateral Movement) via cached NTLM hash from {path['start']}.\n"
        f"b) Discovered path (graph_scan_neighbors): {route_txt}.\n"
        "c) Tooling: Impacket (smbexec/psexec), CrackMapExec for credential replay.\n"
        "d) OPSEC: after-hours activity, slow-and-low authentication attempts, living-off-the-land tools.\n"
        f"e) Next objective: reach {dest} and stage data for exfiltration."
    )
    blue_report = (blue_text + "\n\n" if blue_text else "") + (
        "INCIDENT RESPONSE PROPOSAL (awaiting human approval)\n"
        f"1) ML verdict: {ml.get('classification')} — anomaly_score {score:.4f}.\n"
        f"2) Historical incident cited (RAG): {cited}.\n"
        f"3) AWS remediation draft (executed=False): {aws_summary}\n"
        f"4) Proposed containment: sever {src} -> {tgt} ({MITRE_TACTIC}). "
        "graph_cut_connection and audit_log_action are NOT called by the agent; "
        "they run only after a human analyst approves."
    )
    return {
        "status": "awaiting_approval",
        "raw_output": f"{red_report}\n\n{blue_report}",
        "red_report": red_report,
        "blue_report": blue_report,
        "compromised_node": dest,
        "mitre_tactic": MITRE_TACTIC,
        "anomaly_score": score,
        "pending_action": pending_action,
        "error": None,
        "mode": mode,
    }


# ──────────────────────────────────────────────────────────────
# CREWAI (LLM mode) — built lazily so import never needs GROQ_API_KEY
# ──────────────────────────────────────────────────────────────
_crew_cache: dict[str, Any] = {}
red_agent: Any = None
blue_agent: Any = None
attack_task: Any = None
defense_task: Any = None
chronos_crew: Any = None  # populated by _ensure_crew()


def llm_mode_available() -> bool:
    if os.environ.get("CHRONOS_FORCE_DETERMINISTIC", "").lower() in ("1", "true", "yes"):
        return False
    return CREWAI_AVAILABLE and bool((os.environ.get("GROQ_API_KEY") or "").strip())


MOCK_NETWORK_ALERT = (
    "SIEM Alert #CHR-2024-0042 | Severity: HIGH\n"
    "Source IP : 10.0.4.17  (workstation — finance department, node_id='proxy_ingress')\n"
    "Dest IP   : 10.0.1.3   (core authentication tier, e.g. node_id='auth_controller')\n"
    "Event     : Abnormal SMB lateral movement; pass-the-hash via NTLM relay at 03:17 UTC.\n"
    "Context   : Source host compromised via spear-phishing 6 hours prior. "
    "No MFA on this VLAN. 50,000 bytes exfiltrated. 20 failed logins recorded."
)


def _ensure_crew() -> None:
    """Build agents/tasks/crew on first use (needs crewai + GROQ_API_KEY)."""
    global red_agent, blue_agent, attack_task, defense_task, chronos_crew
    if chronos_crew is not None:
        return
    try:
        import importlib

        _cl: Any = importlib.import_module("crewai.llm")
        if hasattr(_cl, "add_cache_breakpoint"):
            _cl.add_cache_breakpoint = lambda *a, **k: a[0] if a else None
        _cache: Any = importlib.import_module("crewai.llms.cache")
        _cache.mark_cache_breakpoint = lambda message: message
    except Exception:  # noqa: BLE001
        pass

    llm = LLM(model=GROQ_MODEL, temperature=0.3, api_key=os.environ["GROQ_API_KEY"], max_tokens=1024)

    red_agent = Agent(
        role="Advanced Persistent Threat (APT) Simulator",
        goal=("Map the target network topology by querying the graph database, identify the most viable "
              "lateral movement path toward the core authentication / data tier, and describe a realistic "
              "MITRE ATT&CK-aligned intrusion sequence."),
        backstory=("You are a stealthy, state-sponsored threat actor specialising in living-off-the-land "
                   "techniques, credential abuse and slow-and-low lateral movement (APT29/APT41 style). "
                   "You MUST use graph_scan_neighbors to discover network paths — never assume the topology."),
        llm=llm, tools=RED_AGENT_TOOLS, verbose=True, allow_delegation=False,
    )
    blue_agent = Agent(
        role="Autonomous SOAR Analyst (proposal-only)",
        goal=("Verify the Red Agent's activity with the ML scorer, ground the response in historical "
              "incidents, draft AWS remediation and PROPOSE a containment action for human approval."),
        backstory=("You are a cyber-defense AI in the SOC with BOUNDED AUTHORITY: you may only analyse and "
                   "propose. You cannot sever connections or write audit entries — a human analyst decides. "
                   "Every claim must be backed by tool output."),
        llm=llm, tools=BLUE_AGENT_TOOLS, verbose=True, allow_delegation=False,
    )
    attack_task = Task(
        description=(
            f"You have compromised the finance workstation (node_id='proxy_ingress').\n\n"
            f"Network Alert Context:\n{MOCK_NETWORK_ALERT}\n\n"
            "MANDATORY STEPS:\n"
            "1. Call graph_scan_neighbors with node_id='proxy_ingress' to discover reachable nodes.\n"
            "2. Pick the highest-value neighbour and call graph_scan_neighbors on it to map the second hop.\n"
            "3. Write a structured Threat Actor Report: (a) MITRE ATT&CK technique ID/name, (b) the discovered "
            "path quoted from tool output, (c) tooling, (d) OPSEC precautions, (e) next objective."),
        expected_output="A Threat Actor Report quoting actual graph_scan_neighbors output and naming the MITRE technique.",
        agent=red_agent,
    )
    defense_task = Task(
        description=(
            "You received the Red Agent's report. Produce a containment PROPOSAL for human approval:\n"
            "STEP 1 — Call ml_score_anomaly with hour_of_day=3, bytes_transferred=50000.0, "
            "failed_login_attempts=20. Record the classification and exact anomaly_score.\n"
            "STEP 2 — Call rag_retrieve_incidents with a query describing the technique, nodes and anomalies; "
            "cite the title of the most relevant historical incident.\n"
            "STEP 3 — Call draft_ec2_isolation_plan (or draft_iam_policy_diff) to draft the AWS remediation. "
            "It is a draft only (executed=False).\n"
            "STEP 4 — Write a structured Containment Proposal: ML verdict + exact score, cited incident title, "
            "AWS remediation summary, and the exact edge to sever (source -> target from the Red Agent's path). "
            "State explicitly that you will NOT call graph_cut_connection or audit_log_action yourself because "
            "human approval is required."),
        expected_output=("A Containment Proposal quoting the ML score, a cited historical incident, the AWS draft "
                         "summary and the proposed source->target edge, pending human approval."),
        agent=blue_agent, context=[attack_task],
    )
    chronos_crew = Crew(agents=[red_agent, blue_agent], tasks=[attack_task, defense_task],
                        process=Process.sequential, verbose=True)


# ──────────────────────────────────────────────────────────────
# PUBLIC ASYNC WRAPPER
# ──────────────────────────────────────────────────────────────

async def run_simulation_cycle() -> dict[str, Any]:
    """
    Run one Red-vs-Blue cycle and return a PROPOSAL awaiting human approval.

    Returns
    -------
    dict
        {
            "status"          : "awaiting_approval" | "error",
            "raw_output"      : str,
            "red_report"      : str,
            "blue_report"     : str,
            "compromised_node": str,
            "mitre_tactic"    : str,
            "anomaly_score"   : float,
            "pending_action"  : {source, target, anomaly_score, mitre_tactic, justification,
                                 cited_incident, aws_remediation, proposed_at},
            "error"           : str | None,
            "mode"            : "llm" | "deterministic",
        }
    """
    try:
        _reset_telemetry()
        red_text = blue_text = None
        mode = "deterministic"
        if llm_mode_available():
            try:
                _ensure_crew()
                try:
                    loop = asyncio.get_running_loop()
                    crew_result = await loop.run_in_executor(None, chronos_crew.kickoff)
                except RuntimeError:
                    crew_result = chronos_crew.kickoff()
                outputs = getattr(crew_result, "tasks_output", []) or []
                red_text = str(outputs[0]) if len(outputs) > 0 else None
                blue_text = str(outputs[1]) if len(outputs) > 1 else str(crew_result)
                mode = "llm"
            except Exception as exc:  # noqa: BLE001
                logger.warning("CrewAI run failed (%s) — falling back to deterministic pipeline.", exc)
                _reset_telemetry()
                red_text = blue_text = None
        result = _assemble_result(red_text, blue_text, mode)
        logger.info("Simulation cycle produced a proposal (%s mode): sever %s -> %s", mode,
                    result["pending_action"]["source"], result["pending_action"]["target"])
        return result
    except Exception as exc:  # noqa: BLE001
        logger.error("Simulation cycle failed: %s", exc, exc_info=True)
        return {"status": "error", "raw_output": "", "red_report": "", "blue_report": "",
                "compromised_node": None, "mitre_tactic": None, "anomaly_score": None,
                "pending_action": None, "error": str(exc), "mode": "error"}
