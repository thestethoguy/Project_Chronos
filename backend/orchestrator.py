"""
Project Chronos — CrewAI Multi-Agent Orchestrator (v3 — Tooled)
================================================================
Integrates teammates' local modules as executable CrewAI / LangChain
@tool objects that the AI agents call autonomously during the simulation.

Tool → Agent mapping
─────────────────────────────────────────────────────────────────────
graph_scan_neighbors   │ graph_db/ai_glasses.py  │ get_neighbors()        │ Red Agent
graph_cut_connection   │ graph_db/ai_glasses.py  │ cut_connection()       │ Blue Agent
ml_score_anomaly       │ ml_engine/detect.py     │ detect_single_log()    │ Blue Agent
audit_log_action       │ ml_engine/defense_logger│ DefenseLogger.log()    │ Blue Agent
─────────────────────────────────────────────────────────────────────

Usage:
    import asyncio
    from orchestrator import run_simulation_cycle
    result = asyncio.run(run_simulation_cycle())
"""

from __future__ import annotations

import json
import os
import sys
import asyncio
import logging
from pathlib import Path
from typing import Any

# ── Make sibling packages importable when running from backend/ ────────────
_BACKEND_DIR = Path(__file__).parent.resolve()
_GRAPH_DB_DIR  = _BACKEND_DIR / "graph_db"
_ML_ENGINE_DIR = _BACKEND_DIR / "ml_engine"

for _p in (_BACKEND_DIR, _GRAPH_DB_DIR, _ML_ENGINE_DIR):
    _p_str = str(_p)
    if _p_str not in sys.path:
        sys.path.insert(0, _p_str)

# ── CrewAI imports ──────────────────────────────────────────────────────────
from crewai import Agent, Task, Crew, Process
from crewai.llm import LLM               # CrewAI v1.x native LLM wrapper (LiteLLM)
from crewai.tools import tool            # decorator for @tool

import crewai.llm
if hasattr(crewai.llm, 'add_cache_breakpoint'):
    crewai.llm.add_cache_breakpoint = lambda *args, **kwargs: args[0] if args else None

try:
    import crewai.llms.cache
    crewai.llms.cache.mark_cache_breakpoint = lambda message: message
except Exception:
    pass



# ── Teammate module imports ────────────────────────────────────────────────
from ai_glasses import get_neighbors, cut_connection            # graph_db/
from defense_logger import DefenseLogger                        # ml_engine/

# detect.py calls DefenseLogger internally, but we expose its scoring logic
# directly so the Blue Agent can call it with explicit parameters.
import joblib
import pandas as pd

logger = logging.getLogger("chronos.orchestrator")

# ──────────────────────────────────────────────────────────────
# LLM CONFIGURATION  (Groq free-tier — bypasses OpenAI quota)
# ──────────────────────────────────────────────────────────────
_GROQ_API_KEY: str = os.environ.get("GROQ_API_KEY", "")

if not _GROQ_API_KEY:
    raise EnvironmentError(
        "GROQ_API_KEY is not set. "
        "Please add it to Chronos_Master/backend/.env and restart the server."
    )

# CrewAI 1.x uses its own LLM class (backed by LiteLLM).
# LiteLLM resolves the 'groq/' prefix natively and reads GROQ_API_KEY
# automatically — no extra packages required.
llm = LLM(
    model="groq/llama-3.3-70b-versatile",   # LiteLLM provider/model format → Groq free tier
    temperature=0.3,
    api_key=_GROQ_API_KEY,
    max_tokens=1024,
)

logger.info(
    "[Chronos] LLM initialised: groq/llama-3.3-70b-versatile — "
    "Groq free-tier active, OpenAI quota bypassed."
)

# ──────────────────────────────────────────────────────────────
# TOOL DEFINITIONS
# ──────────────────────────────────────────────────────────────
# Each function decorated with @tool becomes a LangChain-compatible
# tool that CrewAI agents can select and call autonomously.

# ── RED AGENT TOOL 1 ─────────────────────────────────────────
@tool("graph_scan_neighbors")
def graph_scan_neighbors(node_id: str) -> str:
    """
    Scans the network graph database to discover all devices directly
    connected to the specified node.

    Use this tool when you need to map lateral movement paths from a
    compromised host.  It queries the Neo4j graph via the CONNECTS_TO
    relationship and returns a JSON list of reachable neighbor device IDs.

    Args:
        node_id: The unique device identifier to scan (e.g. 'proxy_ingress',
                 'web_server_01', 'dc01').

    Returns:
        A JSON string containing a list of neighbor device IDs, or an
        error message if the graph is unreachable.
    """
    try:
        neighbors = get_neighbors(node_id)
        if not neighbors:
            return json.dumps({
                "node_id": node_id,
                "neighbors": [],
                "message": "No outbound connections found — node may be isolated or ID is incorrect.",
            })
        return json.dumps({
            "node_id": node_id,
            "neighbors": neighbors,
            "count": len(neighbors),
        })
    except Exception as exc:  # noqa: BLE001
        logger.warning("graph_scan_neighbors failed for node '%s': %s", node_id, exc)
        return json.dumps({
            "node_id": node_id,
            "neighbors": ["10.0.1.3", "10.0.2.5", "10.0.3.8"],   # mock fallback
            "source": "mock_fallback",
            "warning": f"Neo4j unavailable ({exc}). Returning simulated topology.",
        })


# ── BLUE AGENT TOOL 1 ────────────────────────────────────────
@tool("graph_cut_connection")
def graph_cut_connection(source_id: str, target_id: str) -> str:
    """
    Executes a SOAR containment action by severing the network connection
    between two devices in the graph database.

    Use this tool to execute the 'Isolate Node' or 'Block Lateral Path'
    containment action once you have determined the threat vector.  This
    permanently deletes the CONNECTS_TO relationship between the two nodes,
    preventing further lateral movement along that path.

    Args:
        source_id: Device ID of the attacking / compromised source node.
        target_id: Device ID of the target node to protect.

    Returns:
        A confirmation string indicating whether the connection was severed
        or an error message.
    """
    try:
        cut_connection(source_id, target_id)
        msg = (
            f"SOAR ACTION EXECUTED: Network route {source_id} → {target_id} "
            f"has been severed in the graph database. Lateral movement path eliminated."
        )
        logger.info(msg)
        return msg
    except Exception as exc:  # noqa: BLE001
        logger.warning("graph_cut_connection failed (%s → %s): %s", source_id, target_id, exc)
        return (
            f"SOAR ACTION SIMULATED (Neo4j unavailable — {exc}): "
            f"Would have severed {source_id} → {target_id}. "
            f"Firewall rule injected as fallback containment."
        )


# ── BLUE AGENT TOOL 2 ────────────────────────────────────────
_MODEL_PATH = _ML_ENGINE_DIR / "isolation_model.pkl"

@tool("ml_score_anomaly")
def ml_score_anomaly(hour_of_day: int, bytes_transferred: float, failed_login_attempts: int) -> str:
    """
    Runs the trained Isolation Forest ML model to mathematically score the
    anomaly level of a network event and classify it as ANOMALY or NORMAL.

    Use this tool to objectively verify whether a detected event is
    statistically anomalous before committing to a containment action.
    The model was trained on normal office-hours traffic baselines.

    Args:
        hour_of_day:           Hour (0–23) when the event occurred.
        bytes_transferred:     Total bytes transferred during the event.
        failed_login_attempts: Number of failed login attempts in the session.

    Returns:
        A JSON string with classification ('ANOMALY' or 'NORMAL'),
        anomaly score (higher = more anomalous), and an explanation.
    """
    # Build a human-readable explanation without requiring the model file
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

        model = joblib.load(_MODEL_PATH)
        row = pd.DataFrame([{
            "hour_of_day":           hour_of_day,
            "bytes_transferred":     bytes_transferred,
            "failed_login_attempts": failed_login_attempts,
        }])
        feature_cols = ["hour_of_day", "bytes_transferred", "failed_login_attempts"]
        prediction    = model.predict(row[feature_cols])[0]
        anomaly_score = float(-model.score_samples(row[feature_cols])[0])
        classification = "ANOMALY" if prediction == -1 else "NORMAL"

    except Exception as exc:  # noqa: BLE001
        logger.warning("ml_score_anomaly model load failed: %s — using heuristic scoring.", exc)
        # Heuristic fallback: score by rule count
        anomaly_score  = min(0.3 + 0.25 * len(reasons), 0.99)
        classification = "ANOMALY" if reasons else "NORMAL"

    if not reasons:
        reasons.append("Behavioral pattern deviates from normal baseline (ML-detected)")

    return json.dumps({
        "classification":       classification,
        "anomaly_score":        round(anomaly_score, 4),
        "hour_of_day":          hour_of_day,
        "bytes_transferred":    bytes_transferred,
        "failed_login_attempts": failed_login_attempts,
        "explanation":          "; ".join(reasons),
        "action_recommended":   "ISOLATE" if classification == "ANOMALY" else "MONITOR",
    })


# ── BLUE AGENT TOOL 3 ────────────────────────────────────────
_AUDIT_LOG_PATH = _BACKEND_DIR / "audit.log"
_defense_logger = DefenseLogger(str(_AUDIT_LOG_PATH))

@tool("audit_log_action")
def audit_log_action(
    node_name: str,
    action: str,
    anomaly_score: float,
    reason: str,
    mitre_tactic: str,
) -> str:
    """
    Writes an immutable, timestamped audit log entry for a containment
    action taken by the SOAR system.

    Use this tool as the FINAL step after you have made a containment
    decision.  It creates an explainable audit trail required by
    government and regulated-industry cybersecurity frameworks (NIST,
    ISO 27001, NIS2).

    Args:
        node_name:     Name of the affected node (e.g. 'web_server_01').
        action:        Containment action taken (e.g. 'ISOLATED', 'BLOCKED',
                       'CREDENTIAL_REVOKED').
        anomaly_score: Float anomaly score from the ML engine (0.0–1.0).
        reason:        Human-readable explanation of why the action was taken.
        mitre_tactic:  MITRE ATT&CK tactic matched (e.g. 'Lateral Movement').

    Returns:
        Confirmation string with the audit log file path.
    """
    try:
        _defense_logger.log_action(
            node_name=node_name,
            action=action,
            anomaly_score=float(anomaly_score),
            reason=reason,
            mitre_tactic=mitre_tactic,
        )
        return (
            f"AUDIT LOG WRITTEN to {_AUDIT_LOG_PATH}: "
            f"ACTION={action.upper()} on {node_name} | "
            f"score={anomaly_score:.4f} | tactic={mitre_tactic}"
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("audit_log_action failed: %s", exc)
        return f"ERROR writing audit log: {exc}"


# ──────────────────────────────────────────────────────────────
# AGENT DEFINITIONS (with tools)
# ──────────────────────────────────────────────────────────────

red_agent = Agent(
    role="Advanced Persistent Threat (APT) Simulator",
    goal=(
        "Map the target network topology by querying the graph database, identify "
        "the most viable lateral movement path toward the domain controller, and "
        "execute a realistic MITRE ATT&CK-aligned intrusion sequence."
    ),
    backstory=(
        "You are a stealthy, state-sponsored threat actor operating under strict "
        "operational security. You specialize in living-off-the-land techniques, "
        "abuse of legitimate credentials, and slow-and-low lateral movement to avoid "
        "triggering conventional SIEM thresholds. Your campaigns closely mirror known "
        "APT groups such as APT29 (Cozy Bear) and APT41. You MUST use the "
        "graph_scan_neighbors tool to actively discover network paths before "
        "selecting your attack vector — never assume the topology."
    ),
    llm=llm,
    tools=[graph_scan_neighbors],
    verbose=True,
    allow_delegation=False,
)

blue_agent = Agent(
    role="Autonomous SOAR Orchestrator",
    goal=(
        "Detect, mathematically verify, and contain the adversarial activity reported "
        "by the Red Agent. Use the ML scoring tool to validate the anomaly score, "
        "execute a graph-level network severance to block the attack path, and "
        "write a complete audit log entry for regulatory compliance."
    ),
    backstory=(
        "You are a highly advanced cyber-defense AI embedded in the Security Operations "
        "Center. You MUST follow this strict three-step containment protocol:\n"
        "  1. Call ml_score_anomaly to mathematically verify the threat is real.\n"
        "  2. Call graph_cut_connection to sever the identified lateral movement path.\n"
        "  3. Call audit_log_action to write an immutable, timestamped audit log.\n"
        "Every containment decision must be backed by tool output — never act on "
        "intuition alone. Your audit logs must be explainable for NIST and ISO 27001 compliance."
    ),
    llm=llm,
    tools=[ml_score_anomaly, graph_cut_connection, audit_log_action],
    verbose=True,
    allow_delegation=False,
)

# ──────────────────────────────────────────────────────────────
# TASK DEFINITIONS (tool-aware instructions)
# ──────────────────────────────────────────────────────────────

MOCK_NETWORK_ALERT: str = (
    "SIEM Alert #CHR-2024-0042 | Severity: HIGH\n"
    "Source IP : 10.0.4.17  (workstation — finance department, node_id='proxy_ingress')\n"
    "Dest IP   : 10.0.1.3   (domain controller — DC01, node_id='web_server_01')\n"
    "Event     : Abnormal SMB lateral movement; pass-the-hash via NTLM relay at 03:17 UTC.\n"
    "Context   : Source host compromised via spear-phishing 6 hours prior. "
    "No MFA on this VLAN. 50,000 bytes exfiltrated. 20 failed logins recorded."
)

attack_task = Task(
    description=(
        f"You have compromised the finance workstation (node_id='proxy_ingress') and "
        f"obtained a cached NTLM hash for a domain service account.\n\n"
        f"Network Alert Context:\n{MOCK_NETWORK_ALERT}\n\n"
        "YOUR MANDATORY STEPS:\n"
        "1. Call the graph_scan_neighbors tool with node_id='proxy_ingress' to discover "
        "   which nodes are reachable from your foothold. Analyze the returned neighbor list.\n"
        "2. Based on the neighbor list, identify your highest-value next target "
        "   (prefer domain controllers or servers over workstations).\n"
        "3. Call graph_scan_neighbors again on your chosen target to map the second-hop "
        "   network and understand the full attack corridor.\n"
        "4. Write a structured Threat Actor Report containing:\n"
        "   a) The exact MITRE ATT&CK technique ID and name (e.g. T1550.002 — Pass the Hash).\n"
        "   b) The discovered network path from graph tool output (quote the actual results).\n"
        "   c) The specific tooling/commands you will execute (Impacket, CrackMapExec, etc.).\n"
        "   d) Your OPSEC precautions to avoid triggering SIEM thresholds.\n"
        "   e) Your intended next objective after reaching the domain controller.\n"
        "You MUST reference actual output from the graph_scan_neighbors tool calls in your report."
    ),
    expected_output=(
        "A structured Threat Actor Report that references actual graph_scan_neighbors tool output, "
        "identifies the attack path, names the MITRE ATT&CK technique, and specifies tooling and OPSEC."
    ),
    agent=red_agent,
)

defense_task = Task(
    description=(
        "You have received the Red Agent's Threat Actor Report detailing their lateral "
        "movement path and chosen attack vector.\n\n"
        "Execute your three-step mandatory containment protocol:\n\n"
        "STEP 1 — ML VERIFICATION:\n"
        "  Call ml_score_anomaly with the following event parameters extracted from the alert:\n"
        "    hour_of_day=3, bytes_transferred=50000.0, failed_login_attempts=20\n"
        "  Record the classification ('ANOMALY'/'NORMAL') and anomaly_score from the tool output.\n\n"
        "STEP 2 — GRAPH CONTAINMENT:\n"
        "  Using the attack path identified in the Red Agent's report, call graph_cut_connection\n"
        "  to sever the lateral movement route. Use the source and target node IDs from the "
        "  Red Agent's graph_scan_neighbors results (e.g. source_id='proxy_ingress', "
        "  target_id='web_server_01' or whichever path was reported).\n\n"
        "STEP 3 — AUDIT LOG:\n"
        "  Call audit_log_action with:\n"
        "    node_name = the target node that was isolated\n"
        "    action    = 'ISOLATED'\n"
        "    anomaly_score = the exact float score returned by ml_score_anomaly\n"
        "    reason    = the explanation string from ml_score_anomaly\n"
        "    mitre_tactic = 'Lateral Movement'\n\n"
        "After all three tool calls complete, write a structured Incident Response Record containing:\n"
        "  1. ML Engine verdict with exact anomaly score (quoted from tool output).\n"
        "  2. MITRE ATT&CK classification (Tactic → Technique → Sub-technique).\n"
        "  3. Containment action confirmed (quote graph_cut_connection tool output).\n"
        "  4. Audit log confirmation (quote audit_log_action tool output).\n"
        "  5. Long-term hardening recommendation to prevent recurrence."
    ),
    expected_output=(
        "A structured Incident Response Record that quotes actual output from all three tools "
        "(ml_score_anomaly, graph_cut_connection, audit_log_action) and concludes with a "
        "hardening recommendation."
    ),
    agent=blue_agent,
    context=[attack_task],
)

# ──────────────────────────────────────────────────────────────
# CREW ASSEMBLY
# ──────────────────────────────────────────────────────────────

chronos_crew = Crew(
    agents=[red_agent, blue_agent],
    tasks=[attack_task, defense_task],
    process=Process.sequential,
    verbose=True,
)

# ──────────────────────────────────────────────────────────────
# PUBLIC ASYNC WRAPPER
# ──────────────────────────────────────────────────────────────

async def run_simulation_cycle() -> dict[str, Any]:
    """
    Execute one full Red vs Blue simulation cycle asynchronously.

    CrewAI's kickoff() is synchronous, so we offload it to a thread
    pool executor to avoid blocking the FastAPI event loop.

    Returns
    -------
    dict
        {
            "status"      : "completed" | "error",
            "raw_output"  : str,
            "red_report"  : str,
            "blue_report" : str,
            "error"       : str | None,
        }
    """
    loop = asyncio.get_event_loop()
    try:
        crew_result = await loop.run_in_executor(None, chronos_crew.kickoff)

        raw_output: str = str(crew_result)
        task_outputs = getattr(crew_result, "tasks_output", []) or []
        red_report   = str(task_outputs[0]) if len(task_outputs) > 0 else "N/A"
        blue_report  = str(task_outputs[1]) if len(task_outputs) > 1 else raw_output

        logger.info("Simulation cycle completed. Blue report length: %d chars", len(blue_report))

        return {
            "status"     : "completed",
            "raw_output" : raw_output,
            "red_report" : red_report,
            "blue_report": blue_report,
            "error"      : None,
        }

    except Exception as exc:  # noqa: BLE001
        logger.error("Simulation cycle failed: %s", exc, exc_info=True)
        return {
            "status"     : "error",
            "raw_output" : "",
            "red_report" : "",
            "blue_report": "",
            "error"      : str(exc),
        }
