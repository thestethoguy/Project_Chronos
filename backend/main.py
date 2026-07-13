"""
Project Chronos — FastAPI Orchestrator  (v3 — Live State Engine)
================================================================
Wires the CrewAI multi-agent simulation directly into HTTP routes
so Zasefa's React frontend can poll live agent telemetry via API.

Architecture:
  POST /start_simulation  → kicks off background CrewAI cycle,
                             immediately returns 202 Accepted.
  GET  /simulation_status → returns live snapshot of SIMULATION_STATE,
                             safe to poll every second from the frontend.
  GET  /                  → health-check with server uptime & version.

Environment variables (set in .env):
    OPENAI_API_KEY    — required by orchestrator.py
    NEO4J_URI         — bolt://localhost:7687
    NEO4J_USER        — neo4j username
    NEO4J_PASSWORD    — neo4j password
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Load .env BEFORE importing orchestrator (needs OPENAI_API_KEY) ─────────
from dotenv import load_dotenv
load_dotenv(Path(__file__).parent / ".env")

# ── FastAPI ─────────────────────────────────────────────────────────────────
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# ── Local orchestrator ───────────────────────────────────────────────────────
try:
    from orchestrator import run_simulation_cycle
    _ORCHESTRATOR_LOADED = True
except Exception as _orch_err:          # noqa: BLE001
    _ORCHESTRATOR_LOADED = False
    _ORCHESTRATOR_LOAD_ERROR = str(_orch_err)

# ──────────────────────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s — %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("chronos.main")

# ──────────────────────────────────────────────────────────────
# STEP 1 — GLOBAL IN-MEMORY SIMULATION STATE
# ──────────────────────────────────────────────────────────────
# asyncio.Lock makes all reads/writes thread-safe when the
# background task and the polling endpoint run concurrently.
_STATE_LOCK = asyncio.Lock()

SIMULATION_STATE: dict[str, Any] = {
    "status"          : "idle",
    "latest_event"    : "System baseline normal — no active simulation.",
    "action_taken"    : "None",
    "compromised_node": None,
    "mitre_tactic"    : None,
    "anomaly_score"   : None,
    "red_report"      : None,
    "blue_report"     : None,
    "cycles_run"      : 0,
    "last_updated"    : None,
    "error"           : None,
}

_SERVER_START_TIME = time.time()


def _utc_now() -> str:
    """ISO-8601 UTC timestamp string."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


async def _update_state(**kwargs: Any) -> None:
    """Atomically merge kwargs into SIMULATION_STATE under the lock."""
    async with _STATE_LOCK:
        SIMULATION_STATE.update(kwargs)
        SIMULATION_STATE["last_updated"] = _utc_now()


# ──────────────────────────────────────────────────────────────
# STEP 2 — BACKGROUND WORKER TASK
# ──────────────────────────────────────────────────────────────

async def _simulation_worker() -> None:
    """
    Async background worker that:
      1. Sets status → 'running' immediately.
      2. Calls run_simulation_cycle() (blocking CrewAI in thread pool).
      3. Parses the returned dict and writes live telemetry back to
         SIMULATION_STATE so the polling endpoint always serves fresh data.
    """
    if not _ORCHESTRATOR_LOADED:
        await _update_state(
            status="error",
            latest_event="Orchestrator failed to load — check OPENAI_API_KEY in .env.",
            error=_ORCHESTRATOR_LOAD_ERROR,
        )
        logger.error("Orchestrator not loaded — aborting worker. Error: %s", _ORCHESTRATOR_LOAD_ERROR)
        return

    # ── Phase 0: immediate telemetry update (Red Agent active) ────────────
    await _update_state(
        status="running",
        latest_event="Red Agent active — Mapping attack corridor via graph_scan_neighbors",
        action_taken="Pending",
        compromised_node="proxy_ingress",
        mitre_tactic="Lateral Movement (T1550.002 — Pass the Hash)",
        anomaly_score=None,
        red_report=None,
        blue_report=None,
        error=None,
    )
    logger.info("Simulation cycle started — background worker running.")

    # ── Phase 1: run the full CrewAI Red vs Blue cycle ────────────────────
    try:
        result: dict[str, Any] = await run_simulation_cycle()
    except Exception as exc:            # noqa: BLE001
        await _update_state(
            status="error",
            latest_event="Simulation crashed during CrewAI execution.",
            action_taken="None",
            error=str(exc),
        )
        logger.error("run_simulation_cycle raised an exception: %s", exc, exc_info=True)
        return

    # ── Phase 2: parse result and push live telemetry to SIMULATION_STATE ─
    if result.get("status") == "error":
        await _update_state(
            status="error",
            latest_event="Agent execution failed — see error field.",
            action_taken="None",
            error=result.get("error", "Unknown error"),
        )
        logger.error("Simulation cycle returned error: %s", result.get("error"))
        return

    # --- Extract actionable fields from agent reports --------------------
    blue_report: str = result.get("blue_report", "") or ""
    red_report:  str = result.get("red_report",  "") or ""

    # Detect containment action from Blue Agent's report text
    containment_action = "Containment decision logged — see blue_report"
    for keyword in ("ISOLATED", "SEVERED", "BLOCKED", "REVOKED", "HONEYPOT"):
        if keyword in blue_report.upper():
            containment_action = f"Blue Agent executed: {keyword}"
            break

    # Detect compromised / target node mentioned in Red Agent's report
    compromised_node = "proxy_ingress"           # default from alert context
    for candidate in ("web_server_01", "dc01", "DC01", "10.0.1.3"):
        if candidate in red_report or candidate in blue_report:
            compromised_node = candidate
            break

    # Try to parse anomaly score from blue report (e.g. "score=0.8412")
    anomaly_score: float | None = None
    import re
    _score_match = re.search(r"anomaly[_\s]score[\":\s=]+([0-9]\.[0-9]+)", blue_report, re.IGNORECASE)
    if _score_match:
        try:
            anomaly_score = float(_score_match.group(1))
        except ValueError:
            pass

    # Latest event headline — first non-empty line of blue report
    latest_event_lines = [ln.strip() for ln in blue_report.splitlines() if ln.strip()]
    latest_event = (
        latest_event_lines[0][:200] if latest_event_lines
        else "Blue Agent containment cycle completed."
    )

    async with _STATE_LOCK:
        SIMULATION_STATE.update({
            "status"          : "completed",
            "latest_event"    : latest_event,
            "action_taken"    : containment_action,
            "compromised_node": compromised_node,
            "mitre_tactic"    : "Lateral Movement — T1550.002 (Pass the Hash)",
            "anomaly_score"   : anomaly_score,
            "red_report"      : red_report,
            "blue_report"     : blue_report,
            "cycles_run"      : SIMULATION_STATE["cycles_run"] + 1,
            "last_updated"    : _utc_now(),
            "error"           : None,
        })

    logger.info(
        "Simulation cycle #%d completed. Action: %s | Node: %s",
        SIMULATION_STATE["cycles_run"],
        containment_action,
        compromised_node,
    )


# ──────────────────────────────────────────────────────────────
# STEP 4 — STARTUP DIAGNOSTICS (lifespan hook)
# ──────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Print production-grade diagnostics on startup and clean up on shutdown."""
    divider = "=" * 60
    print(f"\n{divider}")
    print("  Project Chronos — API Server Starting")
    print(divider)
    print(f"  Version        : {app.version}")
    print(f"  Python         : {sys.version.split()[0]}")
    print(f"  Startup time   : {_utc_now()}")

    # Orchestrator import status
    if _ORCHESTRATOR_LOADED:
        print("  Orchestrator   : ✔  orchestrator.py loaded successfully")
        print("  Tools loaded   :")
        print("    • graph_scan_neighbors  → Red Agent  (ai_glasses.get_neighbors)")
        print("    • graph_cut_connection  → Blue Agent (ai_glasses.cut_connection)")
        print("    • ml_score_anomaly      → Blue Agent (detect.py / Isolation Forest)")
        print("    • audit_log_action      → Blue Agent (defense_logger.DefenseLogger)")
    else:
        print(f"  Orchestrator   : ✖  FAILED — {_ORCHESTRATOR_LOAD_ERROR}")

    # Dependency loop check
    _deps = ["fastapi", "crewai", "langchain_openai", "neo4j", "sklearn", "pandas"]
    for _dep in _deps:
        try:
            __import__(_dep)
            print(f"  Dep [{_dep:20s}]: ✔")
        except ImportError:
            print(f"  Dep [{_dep:20s}]: ✖  NOT FOUND")

    print(f"\n  Routes ready:")
    print("    GET  /                  → Health check")
    print("    POST /start_simulation  → Launch CrewAI background cycle")
    print("    GET  /simulation_status → Live state polling endpoint")
    print(f"{divider}\n")
    logger.info("Chronos API startup diagnostics complete.")

    yield  # server runs here

    print(f"\n{divider}")
    print("  Project Chronos — API Server Shutting Down")
    print(f"  Uptime: {time.time() - _SERVER_START_TIME:.1f}s  |  Cycles run: {SIMULATION_STATE['cycles_run']}")
    print(f"{divider}\n")
    logger.info("Chronos API shutdown complete.")


# ──────────────────────────────────────────────────────────────
# APP INITIALISATION
# ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="Chronos Orchestrator API",
    description=(
        "Live backend API for Project Chronos — AI-driven Red vs Blue cyber-simulation. "
        "CrewAI agents (GPT-4o-mini) execute tool-augmented attack and defense cycles "
        "against a Neo4j network graph. Poll /simulation_status for live telemetry."
    ),
    version="3.0.0",
    contact={"name": "Chronos Dev Team"},
    license_info={"name": "MIT"},
    lifespan=lifespan,
)

# ──────────────────────────────────────────────────────────────
# CORS MIDDLEWARE
# ──────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],           # Restrict to frontend origin in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────────────────────────────────────────────────
# ROUTES
# ──────────────────────────────────────────────────────────────

@app.get(
    "/",
    summary="Health Check",
    tags=["System"],
    response_description="Server liveness + uptime metadata.",
)
async def root() -> dict:
    """Root health-check endpoint. Safe to call at any frequency."""
    return {
        "status"              : "Chronos Orchestrator Active",
        "version"             : app.version,
        "uptime_seconds"      : round(time.time() - _SERVER_START_TIME, 1),
        "simulation_status"   : SIMULATION_STATE["status"],
        "cycles_completed"    : SIMULATION_STATE["cycles_run"],
        "orchestrator_loaded" : _ORCHESTRATOR_LOADED,
        "timestamp"           : _utc_now(),
    }


@app.post(
    "/start_simulation",
    status_code=202,
    summary="Start Simulation",
    tags=["Simulation"],
    response_description="Accepted — CrewAI cycle dispatched to background worker.",
)
async def start_simulation(background_tasks: BackgroundTasks) -> dict:
    """
    Triggers a new Chronos Red vs Blue CrewAI simulation cycle.

    Returns HTTP 202 Accepted immediately so the frontend never blocks.
    The background worker updates SIMULATION_STATE in real time — poll
    GET /simulation_status every second to stream live agent telemetry.

    Returns 409 if a simulation is already running to prevent overlapping cycles.
    """
    async with _STATE_LOCK:
        current_status = SIMULATION_STATE["status"]

    if current_status == "running":
        raise HTTPException(
            status_code=409,
            detail="A simulation cycle is already running. "
                   "Poll /simulation_status and wait for status='completed'.",
        )

    # Immediately flip state to 'running' so the frontend knows straight away
    await _update_state(
        status="running",
        latest_event="Red Agent active — Mapping attack corridor via graph_scan_neighbors",
        action_taken="Pending",
        compromised_node="proxy_ingress",
        error=None,
    )

    # Dispatch the heavy async worker to run in the background
    background_tasks.add_task(_simulation_worker)
    logger.info("Simulation background worker dispatched.")

    return {
        "status"    : "Simulation initiated in background",
        "message"   : "Poll GET /simulation_status for live agent telemetry.",
        "timestamp" : _utc_now(),
    }


@app.get(
    "/simulation_status",
    summary="Get Live Simulation Status",
    tags=["Simulation"],
    response_description="Current snapshot of SIMULATION_STATE — safe to poll every second.",
)
async def simulation_status() -> dict:
    """
    Returns the live snapshot of SIMULATION_STATE.

    Designed for 1-second polling from Zasefa's React frontend.
    The state transitions are:
      idle → running → completed | error

    Fields:
      status           : 'idle' | 'running' | 'completed' | 'error'
      latest_event     : Human-readable latest agent action (updates mid-cycle)
      action_taken     : SOAR containment decision (populated on completion)
      compromised_node : Target node identified by Red Agent
      mitre_tactic     : ATT&CK classification
      anomaly_score    : ML Engine float score (0.0–1.0, higher = more anomalous)
      red_report       : Full Red Agent Threat Actor Report text
      blue_report      : Full Blue Agent Incident Response Record text
      cycles_run       : Total completed simulation cycles this session
      last_updated     : ISO-8601 UTC timestamp of last state mutation
      error            : Error message if status='error', else null
    """
    async with _STATE_LOCK:
        # Return a shallow copy so the lock is released immediately
        snapshot = dict(SIMULATION_STATE)
    return snapshot


@app.post(
    "/reset_simulation",
    summary="Reset Simulation State",
    tags=["Simulation"],
    response_description="Resets state to idle so a new cycle can be started.",
)
async def reset_simulation() -> dict:
    """
    Resets SIMULATION_STATE to idle.

    Use this between test cycles when you want to re-trigger
    /start_simulation without waiting for the server to restart.
    Cannot reset while a cycle is actively running.
    """
    async with _STATE_LOCK:
        if SIMULATION_STATE["status"] == "running":
            raise HTTPException(
                status_code=409,
                detail="Cannot reset while a simulation is running.",
            )
        cycles = SIMULATION_STATE["cycles_run"]   # preserve cycle counter
        SIMULATION_STATE.clear()
        SIMULATION_STATE.update({
            "status"          : "idle",
            "latest_event"    : "State reset — system baseline normal.",
            "action_taken"    : "None",
            "compromised_node": None,
            "mitre_tactic"    : None,
            "anomaly_score"   : None,
            "red_report"      : None,
            "blue_report"     : None,
            "cycles_run"      : cycles,
            "last_updated"    : _utc_now(),
            "error"           : None,
        })

    logger.info("Simulation state reset to idle.")
    return {"status": "idle", "message": "Simulation state reset successfully."}
