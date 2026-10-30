"""Session routes backed by MongoDB. Drop-in replacement for the SIMULATION_STATE handlers."""
from fastapi import APIRouter, BackgroundTasks, HTTPException

from backend.db.session_store import (
    get_current_session,
    reset_session,
    try_start_session,
    update_current_session,
)

router = APIRouter(tags=["simulation"])


def run_cycle_in_background():  # replace body with your existing orchestrator call
    """Wrap your existing orchestrator kickoff here. On finish call
    update_current_session(status="completed", ...) ; on exception
    update_current_session(status="error", error=str(exc))."""
    raise NotImplementedError("Hook your existing orchestrator cycle in here.")


@router.post("/start_simulation")
async def start_simulation(background_tasks: BackgroundTasks):
    session = try_start_session()  # atomic check-and-set -> no race
    if session is None:
        raise HTTPException(status_code=409, detail="A simulation is already running.")
    background_tasks.add_task(run_cycle_in_background)
    return {"status": "running", "session_id": session["session_id"]}


@router.get("/simulation_status")
async def simulation_status():
    return get_current_session()


@router.post("/reset_simulation")
async def reset_simulation():
    return reset_session()
