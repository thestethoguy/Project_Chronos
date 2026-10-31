"""POST /copilot/ask (Guide Section 9.4). Works with Gemini, Groq+Neo4j, or fully offline (rules + topology mirror)."""
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.concurrency import run_in_threadpool

from backend.copilot.answer import answer_question
from backend.db.neo4j_driver import get_driver

router = APIRouter(tags=["copilot"])


@router.post("/copilot/ask")
async def copilot_ask(payload: dict[str, Any], request: Request) -> dict[str, Any]:
    question = str(payload.get("question", "")).strip()
    if not question:
        raise HTTPException(status_code=400, detail="Question must not be empty.")
    topology_override = payload.get("topology") if isinstance(payload.get("topology"), dict) else None
    session_context = payload.get("session_context") if isinstance(payload.get("session_context"), dict) else None
    history = payload.get("history") if isinstance(payload.get("history"), list) else None
    gemini_api_key = request.headers.get("x-gemini-key") or payload.get("gemini_api_key")
    try:
        # get_driver() is None when Neo4j is unconfigured/unreachable -> answer from the mirror.
        return await run_in_threadpool(
            lambda: answer_question(
                get_driver(),
                question,
                topology_override=topology_override,
                session_context=session_context,
                history=history,
                gemini_api_key=str(gemini_api_key) if gemini_api_key else None,
            )
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
