"""MongoDB-backed replacement for the in-memory SIMULATION_STATE dict (Guide Section 7.5).

Document shape is a strict superset of the Phase-1 dict so existing frontend code keeps working.
`pending_action` is reserved for Person C's HITL gate.
"""
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from pymongo import ReturnDocument

from backend.db.mongo import sessions_collection

ACTIVE_STATUSES = ["running", "awaiting_approval"]

# Injectable for tests (e.g. mongomock): a zero-arg callable returning a Collection.
_collection_factory: Callable = sessions_collection


def set_collection_factory(factory: Callable) -> None:
    global _collection_factory
    _collection_factory = factory


def _col():
    return _collection_factory()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _blank_session(cycles_run: int = 0) -> dict:
    now = _now()
    return {
        "session_id": uuid.uuid4().hex[:8],
        "status": "idle",
        "latest_event": "",
        "action_taken": "",
        "compromised_node": None,
        "mitre_tactic": None,
        "anomaly_score": None,
        "red_report": None,
        "blue_report": None,
        "cycles_run": cycles_run,
        "pending_action": None,
        "created_at": now,
        "last_updated": now,
        "error": None,
    }


def get_current_session() -> dict:
    """Most recently updated session; creates an idle one if the collection is empty."""
    doc = _col().find_one({}, sort=[("last_updated", -1), ("_id", -1)], projection={"_id": 0})
    if doc is None:
        doc = _blank_session()
        _col().insert_one(dict(doc))
    return doc


def update_current_session(**fields: Any) -> dict:
    """Single write path for every SIMULATION_STATE mutation."""
    current = get_current_session()
    fields["last_updated"] = _now()
    _col().update_one(
        {"session_id": current["session_id"]}, {"$set": fields}, upsert=True
    )
    return get_current_session()


def try_start_session() -> Optional[dict]:
    """Atomically claim the session for a new run.

    Returns the new running session, or None if one is already active (caller -> HTTP 409).
    The status check and the write to 'running' happen in ONE find_one_and_update, so two
    rapid POST /start_simulation calls can never both succeed (Guide 7.5, Step 4).
    """
    current = get_current_session()
    new_id = uuid.uuid4().hex[:8]
    claimed = _col().find_one_and_update(
        {"session_id": current["session_id"], "status": {"$nin": ACTIVE_STATUSES}},
        {
            "$set": {
                "session_id": new_id,
                "status": "running",
                "latest_event": "Simulation started",
                "action_taken": "",
                "compromised_node": None,
                "mitre_tactic": None,
                "anomaly_score": None,
                "red_report": None,
                "blue_report": None,
                "pending_action": None,
                "error": None,
                "created_at": _now(),
                "last_updated": _now(),
            },
            "$inc": {"cycles_run": 1},
        },
        return_document=ReturnDocument.AFTER,
    )
    if claimed is not None:
        claimed.pop("_id", None)
    return claimed


def reset_session() -> dict:
    """POST /reset_simulation: back to idle, preserving cycles_run (Phase-1 behaviour)."""
    cycles = get_current_session().get("cycles_run", 0)
    fresh = _blank_session(cycles_run=cycles)
    _col().insert_one(dict(fresh))
    return fresh
