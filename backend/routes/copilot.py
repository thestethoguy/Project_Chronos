"""POST /copilot/ask (Guide Section 9.4). Works with Groq+Neo4j or fully offline (rules + topology mirror)."""
from fastapi import APIRouter, HTTPException
from fastapi.concurrency import run_in_threadpool

from backend.copilot.answer import answer_question
from backend.db.neo4j_driver import get_driver

router = APIRouter(tags=["copilot"])


@router.post("/copilot/ask")
async def copilot_ask(payload: dict):
    question = str(payload.get("question", "")).strip()
    if not question:
        raise HTTPException(status_code=400, detail="Question must not be empty.")
    try:
        # get_driver() is None when Neo4j is unconfigured/unreachable -> answer from the mirror.
        return await run_in_threadpool(lambda: answer_question(get_driver(), question))
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))