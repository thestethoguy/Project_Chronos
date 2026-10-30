"""POST /upload_topology and GET /topology (Guide Sections 7.3 / 7.4).

Works with or without Neo4j: uploads always update the in-memory mirror (and Neo4j when reachable);
GET /topology reads Neo4j when reachable & populated, else the mirror.
"""
import json

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool
from pydantic import ValidationError

from backend.db import topology_store
from backend.schemas.topology import NetworkTopologyFile

router = APIRouter(tags=["topology"])

MAX_UPLOAD_BYTES = 2 * 1024 * 1024  # 2 MB: plenty for a topology, blocks abuse


@router.post("/upload_topology")
async def upload_topology(topology_file: UploadFile = File(...)):
    if not (topology_file.filename or "").lower().endswith(".json"):
        raise HTTPException(status_code=400, detail="File must be a .json file.")

    raw = await topology_file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large (max 2 MB).")

    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="File is not valid JSON.")

    if not isinstance(parsed, dict):
        raise HTTPException(status_code=422, detail="Top-level JSON must be an object.")
    try:
        topology = NetworkTopologyFile(**parsed)
    except ValidationError as e:
        # Readable messages for the frontend instead of raw pydantic internals
        msgs = [f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in e.errors()]
        raise HTTPException(status_code=422, detail="; ".join(msgs[:5]))

    return await run_in_threadpool(topology_store.store_topology, topology.model_dump())


@router.get("/topology")
async def get_topology():
    return await run_in_threadpool(topology_store.get_topology)
