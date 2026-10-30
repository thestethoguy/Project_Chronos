"""Lazy, failure-tolerant shared Neo4j driver.

Importing this module never raises. `get_driver()` returns None when Neo4j is unconfigured
(NEO4J_URI / NEO4J_PASSWORD missing) or unreachable; callers then use the in-memory topology
mirror (backend/db/topology_store.py). Availability is cached (long on success, short on failure)
so an offline Neo4j doesn't add latency to every request.
"""
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Optional

try:
    from dotenv import load_dotenv

    load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")
except ImportError:
    pass

logger = logging.getLogger("chronos.neo4j")

_OK_TTL = 300.0
_FAIL_TTL = 30.0
_lock = threading.Lock()
_state: dict[str, Any] = {"driver": None, "ok": None, "checked_at": 0.0}


def _config() -> Optional[tuple[str, str, str]]:
    uri = (os.environ.get("NEO4J_URI") or "").strip()
    password = os.environ.get("NEO4J_PASSWORD") or ""
    user = (os.environ.get("NEO4J_USER") or "neo4j").strip()
    if not uri or not password:
        return None
    return uri, user, password


def reset_driver_cache() -> None:
    """Forget the cached connection check (used by tests / after env changes)."""
    with _lock:
        drv = _state["driver"]
        _state.update(driver=None, ok=None, checked_at=0.0)
    if drv is not None:
        try:
            drv.close()
        except Exception:  # noqa: BLE001
            pass


def get_driver():
    """Connected neo4j Driver, or None if unconfigured/unreachable."""
    with _lock:
        cfg = _config()
        if cfg is None:
            return None
        age = time.time() - _state["checked_at"]
        if _state["ok"] is True and age < _OK_TTL:
            return _state["driver"]
        if _state["ok"] is False and age < _FAIL_TTL:
            return None
        try:
            from neo4j import GraphDatabase

            uri, user, password = cfg
            driver = GraphDatabase.driver(uri, auth=(user, password), connection_timeout=3,
                                          max_transaction_retry_time=2)
            driver.verify_connectivity()
            _state.update(driver=driver, ok=True, checked_at=time.time())
            logger.info("Connected to Neo4j at %s", uri)
            return driver
        except Exception as exc:  # noqa: BLE001 - ImportError, ServiceUnavailable, AuthError ...
            logger.warning("Neo4j unavailable (%s) - using in-memory topology mirror.", type(exc).__name__)
            _state.update(driver=None, ok=False, checked_at=time.time())
            return None


def neo4j_available() -> bool:
    return get_driver() is not None


def neo4j_status() -> str:
    if _config() is None:
        return "not_configured"
    return "connected" if neo4j_available() else "unreachable"
