"""
Project Chronos — FastAPI Backend (v2.0.0 — Phase 2: Human-in-the-Loop)
=======================================================================
Unifies Phase 1 (CrewAI Red-vs-Blue simulation) with Phase 2:
  * MongoDB-backed session store (falls back to in-memory when MongoDB is unreachable)
  * Topology upload / live topology (Neo4j when reachable, in-memory mirror otherwise)
  * HITL gate: the Blue Agent only PROPOSES; a human approves/rejects
  * RAG-grounded proposals, AWS remediation drafts and the SOC Copilot

Endpoints
  GET  /                  health (uptime, version, orchestrator, database, simulation status)
  POST /upload_topology   validate + store a network_topology.json
  GET  /topology          current topology {devices, connections}
  POST /start_simulation  atomically claim the session (409 if running/awaiting_approval) + background run
  GET  /simulation_status current session document (includes pending_action)
  POST /approve_action    human approves  -> graph edge severed + audit entry
  POST /reject_action     human rejects   -> graph untouched + audit entry
  POST /reset_simulation  back to idle (409 while running)
  POST /copilot/ask       SOC Copilot (read-only Cypher; Groq or offline rules)
  GET  /audit_logs        recent audit.log entries

Run from <repo_root>:  uvicorn backend.main:app      or from backend/:  uvicorn main:app
"""

from __future__ import annotations

import asyncio
import logging
import re
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:  # dual-mode import paths (see backend/_bootstrap.py)
    import _bootstrap  # noqa: F401
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _bootstrap  # noqa: F401

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware

from backend.db.mongo import using_fallback
from backend.db.neo4j_driver import neo4j_status
from backend.db.session_store import (
    get_current_session,
    reset_session,
    try_start_session,
    update_current_session,
)
from backend.routes import copilot as copilot_routes
from backend.routes import topology as topology_routes

# ── Orchestrator (bare import on purpose: one module object shared with tests) ─────────────
orch: Any = None
try:
    import orchestrator as _orch_mod

    orch = _orch_mod
    _ORCHESTRATOR_LOADED = True
    _ORCHESTRATOR_LOAD_ERROR = ""
except Exception as _orch_err:  # noqa: BLE001
    _ORCHESTRATOR_LOADED = False
    _ORCHESTRATOR_LOAD_ERROR = str(_orch_err)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s — %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("chronos.main")

APP_VERSION = "2.0.0"
_SERVER_START_TIME = time.time()
_HITL_LOCK = asyncio.Lock()  # serialises approve/reject so a decision can't be applied twice


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ──────────────────────────────────────────────────────────────
# BACKGROUND WORKER
# ──────────────────────────────────────────────────────────────

async def _simulation_worker() -> None:
    """Runs one cycle and parks the session in `awaiting_approval` with a pending proposal."""
    if not _ORCHESTRATOR_LOADED:
        update_current_session(
            status="error",
            latest_event="Orchestrator failed to load — see error field.",
            error=_ORCHESTRATOR_LOAD_ERROR,
        )
        logger.error("Orchestrator not loaded — aborting worker: %s", _ORCHESTRATOR_LOAD_ERROR)
        return

    update_current_session(
        latest_event="Red Agent active — mapping attack corridor via graph_scan_neighbors",
        action_taken="Pending",
    )
    try:
        result: dict[str, Any] = await orch.run_simulation_cycle()
    except Exception as exc:  # noqa: BLE001
        update_current_session(status="error", latest_event="Simulation crashed during execution.",
                               action_taken="None", error=str(exc))
        logger.error("run_simulation_cycle raised: %s", exc, exc_info=True)
        return

    if result.get("status") == "error" or not result.get("pending_action"):
        update_current_session(status="error", latest_event="Agent execution failed — see error field.",
                               action_taken="None", error=result.get("error") or "No proposal produced")
        return

    action = result["pending_action"]
    update_current_session(
        status="awaiting_approval",
        latest_event=(f"Blue Agent proposes severing {action['source']} -> {action['target']} "
                      f"— awaiting human approval."),
        action_taken="Pending human approval",
        compromised_node=result.get("compromised_node"),
        mitre_tactic=result.get("mitre_tactic"),
        anomaly_score=result.get("anomaly_score"),
        red_report=result.get("red_report"),
        blue_report=result.get("blue_report"),
        pending_action=action,
        error=None,
    )
    logger.info("Proposal ready: sever %s -> %s (awaiting approval)", action["source"], action["target"])


# ──────────────────────────────────────────────────────────────
# LIFESPAN
# ──────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    divider = "=" * 60
    print(f"\n{divider}\n  Project Chronos — API Server Starting (v{APP_VERSION})\n{divider}")
    print(f"  Python       : {sys.version.split()[0]}")
    if _ORCHESTRATOR_LOADED:
        mode = "LLM (CrewAI + Groq)" if orch.llm_mode_available() else "deterministic tool pipeline"
        print(f"  Orchestrator : loaded — {mode}")
    else:
        print(f"  Orchestrator : FAILED — {_ORCHESTRATOR_LOAD_ERROR}")
    print(f"  Database     : {'in-memory fallback' if using_fallback() else 'MongoDB'}")
    print(f"  Neo4j        : {neo4j_status()}")
    print(f"{divider}\n")
    yield
    print(f"\n  Project Chronos — shutting down (uptime {time.time() - _SERVER_START_TIME:.1f}s)\n")


# ──────────────────────────────────────────────────────────────
# APP
# ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="Chronos Orchestrator API",
    description=("Live backend for Project Chronos — AI Red vs Blue simulation with human-in-the-loop "
                 "containment approval, RAG-grounded proposals and a SOC Copilot."),
    version=APP_VERSION,
    contact={"name": "Chronos Dev Team"},
    license_info={"name": "MIT"},
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict to the frontend origin in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(topology_routes.router)
app.include_router(copilot_routes.router)


@app.get("/", summary="Health Check", tags=["System"])
async def root() -> dict:
    session = await run_in_threadpool(get_current_session)
    fallback = await run_in_threadpool(using_fallback)
    return {
        "status": "Chronos Orchestrator Active",
        "version": APP_VERSION,
        "uptime_seconds": round(time.time() - _SERVER_START_TIME, 1),
        "orchestrator": {
            "loaded": _ORCHESTRATOR_LOADED,
            "mode": ("llm" if (_ORCHESTRATOR_LOADED and orch.llm_mode_available()) else "deterministic"),
            "crewai_available": bool(_ORCHESTRATOR_LOADED and orch.CREWAI_AVAILABLE),
            "error": _ORCHESTRATOR_LOAD_ERROR or None,
        },
        "orchestrator_loaded": _ORCHESTRATOR_LOADED,
        "database": {"type": "in-memory" if fallback else "mongodb",
                     "status": "fallback" if fallback else "connected"},
        "neo4j": neo4j_status(),
        "simulation_status": session.get("status"),
        "cycles_completed": session.get("cycles_run", 0),
        "timestamp": _utc_now(),
    }


@app.post("/start_simulation", status_code=202, summary="Start Simulation", tags=["Simulation"])
async def start_simulation(background_tasks: BackgroundTasks) -> dict:
    """Atomically claims the session. 409 if a cycle is running or awaiting approval."""
    session = await run_in_threadpool(try_start_session)
    if session is None:
        raise HTTPException(
            status_code=409,
            detail="A simulation is already running or awaiting analyst approval. "
                   "Resolve it via /approve_action or /reject_action (or /reset_simulation).",
        )
    background_tasks.add_task(_simulation_worker)
    return {
        "status": "running",
        "session_id": session["session_id"],
        "message": "Poll GET /simulation_status for live telemetry.",
        "timestamp": _utc_now(),
    }


@app.get("/simulation_status", summary="Get Live Simulation Status", tags=["Simulation"])
async def simulation_status() -> dict:
    return await run_in_threadpool(get_current_session)


async def _require_pending() -> tuple[dict, dict]:
    session = await run_in_threadpool(get_current_session)
    action = session.get("pending_action")
    if session.get("status") != "awaiting_approval" or not action:
        raise HTTPException(status_code=409, detail="No pending action is awaiting approval.")
    return session, action


@app.post("/approve_action", summary="Approve pending containment", tags=["Simulation"])
async def approve_action() -> dict:
    async with _HITL_LOCK:
        _session, action = await _require_pending()
        try:
            await run_in_threadpool(orch.perform_graph_cut, action["source"], action["target"])
            await run_in_threadpool(
                lambda: orch.write_audit_entry(
                    node_name=action["target"],
                    action="CONNECTION_SEVERED",
                    anomaly_score=action["anomaly_score"],
                    reason=action["justification"],
                    mitre_tactic=action.get("mitre_tactic"),
                    approved_by="human-analyst",
                )
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("approve_action failed: %s", exc, exc_info=True)
            raise HTTPException(status_code=500, detail=f"Could not execute containment: {exc}")

        taken = f"Severed {action['source']} -> {action['target']} (Approved by human-analyst)"
        await run_in_threadpool(
            lambda: update_current_session(status="completed", pending_action=None, action_taken=taken,
                                           latest_event=taken, error=None)
        )
    logger.info(taken)
    return {"status": "completed", "action_taken": taken}


@app.post("/reject_action", summary="Reject pending containment", tags=["Simulation"])
async def reject_action() -> dict:
    async with _HITL_LOCK:
        _session, action = await _require_pending()
        try:
            await run_in_threadpool(
                lambda: orch.write_audit_entry(
                    node_name=action["target"],
                    action="PROPOSAL_REJECTED",
                    anomaly_score=action["anomaly_score"],
                    reason="Rejected by human analyst",
                    mitre_tactic=action.get("mitre_tactic"),
                    approved_by="human-analyst",
                )
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("reject_action audit failed: %s", exc, exc_info=True)
            raise HTTPException(status_code=500, detail=f"Could not write audit entry: {exc}")

        taken = "No action taken (proposal rejected by analyst)."
        await run_in_threadpool(
            lambda: update_current_session(status="completed", pending_action=None, action_taken=taken,
                                           latest_event=taken, error=None)
        )
    return {"status": "completed", "action_taken": taken}


@app.post("/reset_simulation", summary="Reset Simulation State", tags=["Simulation"])
async def reset_simulation() -> dict:
    session = await run_in_threadpool(get_current_session)
    if session.get("status") == "running":
        raise HTTPException(status_code=409, detail="Cannot reset while a simulation is running.")
    fresh = await run_in_threadpool(reset_session)
    return {"status": "idle", "message": "Simulation state reset successfully.",
            "session_id": fresh["session_id"]}


_AUDIT_LINE = re.compile(
    r"^\[(?P<timestamp>[^\]]+)\] ACTION TAKEN: (?P<action>\S+) (?P<node>\S+?)\. "
    r"REASON: Anomaly score (?P<score>[0-9.]+)"
    r"(?:.*?APPROVED BY: (?P<approved_by>[^.]+)\.)?"
)


@app.get("/audit_logs", summary="Recent audit log entries", tags=["System"])
async def audit_logs(limit: int = Query(50, ge=1, le=500)) -> dict:
    path = orch.get_audit_log_path() if _ORCHESTRATOR_LOADED else Path(__file__).parent / "audit.log"

    def _read() -> list[dict]:
        if not path.exists():
            return []
        lines = [ln.strip() for ln in path.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
        entries = []
        for ln in lines[-limit:]:
            m = _AUDIT_LINE.match(ln)
            g = m.groupdict() if m else {}
            entries.append({
                "timestamp": g.get("timestamp"),
                "action": g.get("action"),
                "node": g.get("node"),
                "anomaly_score": float(g["score"]) if g.get("score") else None,
                "approved_by": g.get("approved_by"),
                "raw": ln,
            })
        return list(reversed(entries))  # newest first

    entries = await run_in_threadpool(_read)
    return {"count": len(entries), "entries": entries}
