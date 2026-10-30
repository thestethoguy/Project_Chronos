"""Shared MongoDB client with offline resilience.

Resolution order (decided once, then cached):
  1. MONGODB_URI set + reachable (3s ping)  -> real pymongo.MongoClient  (Atlas / local mongod)
  2. otherwise, `mongomock` installed       -> mongomock.MongoClient()   (in-memory)
  3. otherwise                              -> built-in lightweight in-memory client

So sessions_collection() / incident_logs_collection() never crash in offline mode.
"""
import copy
import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

try:
    from dotenv import load_dotenv

    load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")
except ImportError:  # python-dotenv optional at import time
    pass

logger = logging.getLogger("chronos.mongo")

_USING_FALLBACK = False


# ── lightweight in-memory fallback (only used when mongomock is not installed) ──────────────
_MISSING = object()


def _get_path(doc: dict, path: str):
    cur: Any = doc
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return _MISSING
    return cur


def _match(doc: dict, flt: dict) -> bool:
    for key, cond in (flt or {}).items():
        if key == "$and":
            if not all(_match(doc, f) for f in cond):
                return False
            continue
        if key == "$or":
            if not any(_match(doc, f) for f in cond):
                return False
            continue
        val = _get_path(doc, key)
        if isinstance(cond, dict) and any(k.startswith("$") for k in cond):
            for op, arg in cond.items():
                present = val is not _MISSING
                try:
                    ok = {
                        "$eq": lambda: present and val == arg,
                        "$ne": lambda: (not present) or val != arg,
                        "$in": lambda: present and val in arg,
                        "$nin": lambda: (not present) or val not in arg,
                        "$gt": lambda: present and val > arg,
                        "$gte": lambda: present and val >= arg,
                        "$lt": lambda: present and val < arg,
                        "$lte": lambda: present and val <= arg,
                        "$exists": lambda: present == bool(arg),
                    }[op]()
                except KeyError:
                    raise NotImplementedError(f"in-memory fallback does not support {op}")
                except TypeError:
                    ok = False
                if not ok:
                    return False
        elif val is _MISSING or val != cond:
            return False
    return True


def _project(doc: dict, projection: dict | None) -> dict:
    doc = copy.deepcopy(doc)
    if not projection:
        return doc
    include = {k for k, v in projection.items() if v and k != "_id"}
    if include:
        out = {k: doc[k] for k in include if k in doc}
        if projection.get("_id", 1):
            out["_id"] = doc.get("_id")
        return out
    for k, v in projection.items():
        if not v:
            doc.pop(k, None)
    return doc


class _InsertOneResult:
    def __init__(self, inserted_id):
        self.inserted_id = inserted_id


class _InsertManyResult:
    def __init__(self, ids):
        self.inserted_ids = ids


class _UpdateResult:
    def __init__(self, matched, modified, upserted_id=None):
        self.matched_count, self.modified_count, self.upserted_id = matched, modified, upserted_id


class _DeleteResult:
    def __init__(self, n):
        self.deleted_count = n


class InMemoryCollection:
    """Minimal pymongo.Collection stand-in. NOT thread-safe beyond the GIL; fine for demos/tests."""

    def __init__(self, name: str = "col"):
        self.name = name
        self._docs: list[dict] = []
        self._seq = 0

    def _new_id(self) -> int:
        self._seq += 1
        return self._seq

    def insert_one(self, doc: dict):
        doc = copy.deepcopy(doc)
        doc.setdefault("_id", self._new_id())
        self._docs.append(doc)
        return _InsertOneResult(doc["_id"])

    def insert_many(self, docs):
        return _InsertManyResult([self.insert_one(d).inserted_id for d in docs])

    def find(self, flt: dict | None = None, projection: dict | None = None, sort=None, limit: int = 0):
        rows = [d for d in self._docs if _match(d, flt or {})]
        for key, direction in reversed(sort or []):
            rows.sort(
                key=lambda d, k=key: (_get_path(d, k) is _MISSING, _get_path(d, k) if _get_path(d, k) is not _MISSING else 0),
                reverse=direction < 0,
            )
        if limit:
            rows = rows[:limit]
        return iter([_project(d, projection) for d in rows])

    def find_one(self, flt: dict | None = None, projection: dict | None = None, sort=None):
        return next(self.find(flt, projection, sort, limit=1), None)

    @staticmethod
    def _apply_update(doc: dict, update: dict) -> None:
        for k, v in update.get("$set", {}).items():
            doc[k] = copy.deepcopy(v)
        for k, v in update.get("$inc", {}).items():
            doc[k] = doc.get(k, 0) + v
        for k in update.get("$unset", {}):
            doc.pop(k, None)

    def update_one(self, flt: dict, update: dict, upsert: bool = False):
        for d in self._docs:
            if _match(d, flt):
                self._apply_update(d, update)
                return _UpdateResult(1, 1)
        if upsert:
            new = {k: v for k, v in flt.items() if not k.startswith("$") and not isinstance(v, dict)}
            self._apply_update(new, update)
            return _UpdateResult(0, 0, self.insert_one(new).inserted_id)
        return _UpdateResult(0, 0)

    def find_one_and_update(self, flt: dict, update: dict, projection=None, sort=None, upsert=False,
                            return_document=False):
        rows = [d for d in self._docs if _match(d, flt)]
        target = rows[0] if rows else None
        if target is None:
            if not upsert:
                return None
            self.update_one(flt, update, upsert=True)
            target = self._docs[-1]
            return _project(target, projection) if return_document else None
        before = copy.deepcopy(target)
        self._apply_update(target, update)
        # pymongo: ReturnDocument.AFTER == True, BEFORE == False
        return _project(target if return_document else before, projection)

    def delete_many(self, flt: dict | None = None):
        keep = [d for d in self._docs if not _match(d, flt or {})]
        n = len(self._docs) - len(keep)
        self._docs = keep
        return _DeleteResult(n)

    def count_documents(self, flt: dict | None = None, **_kw) -> int:
        return sum(1 for d in self._docs if _match(d, flt or {}))

    def aggregate(self, pipeline: list[dict]):
        rows = [copy.deepcopy(d) for d in self._docs]
        for stage in pipeline:
            (op, arg), = stage.items()
            if op == "$match":
                rows = [d for d in rows if _match(d, arg)]
            elif op == "$limit":
                rows = rows[:arg]
            elif op == "$skip":
                rows = rows[arg:]
            elif op == "$project":
                rows = [_project(d, arg) for d in rows]
            elif op == "$sort":
                for key, direction in reversed(list(arg.items())):
                    rows.sort(key=lambda d, k=key: (_get_path(d, k) is _MISSING, _get_path(d, k) if _get_path(d, k) is not _MISSING else 0),
                              reverse=direction < 0)
            elif op == "$count":
                rows = [{arg: len(rows)}]
            else:  # includes $vectorSearch -> callers fall back to Python-side ranking
                raise NotImplementedError(f"in-memory fallback does not support {op}")
        return iter(rows)


class InMemoryDatabase:
    def __init__(self):
        self._cols: dict[str, InMemoryCollection] = {}

    def __getitem__(self, name: str) -> InMemoryCollection:
        return self._cols.setdefault(name, InMemoryCollection(name))


class InMemoryClient:
    def __init__(self):
        self._dbs: dict[str, InMemoryDatabase] = {}

    def __getitem__(self, name: str) -> InMemoryDatabase:
        return self._dbs.setdefault(name, InMemoryDatabase())


# ── client selection ───────────────────────────────────────────────────────────────────────
def _fallback_client():
    global _USING_FALLBACK
    _USING_FALLBACK = True
    try:
        import mongomock

        logger.warning("Using in-memory mongomock database (data is NOT persisted).")
        return mongomock.MongoClient()
    except ImportError:
        logger.warning("mongomock not installed; using built-in in-memory store (data is NOT persisted).")
        return InMemoryClient()


@lru_cache(maxsize=1)
def _client():
    uri = (os.environ.get("MONGODB_URI") or "").strip()
    if not uri:
        logger.warning("MONGODB_URI is missing or empty - falling back to an in-memory database.")
        return _fallback_client()
    try:
        from pymongo import MongoClient

        client = MongoClient(uri, serverSelectionTimeoutMS=3000)
        client.admin.command("ping")
        logger.info("Connected to MongoDB.")
        return client
    except Exception as exc:  # noqa: BLE001 - ImportError, ServerSelectionTimeoutError, ConfigurationError...
        logger.warning("MongoDB unreachable (%s: %s) - falling back to an in-memory database.",
                       type(exc).__name__, str(exc)[:120])
        return _fallback_client()


def using_fallback() -> bool:
    """True when the in-memory fallback is active (forces client selection first)."""
    _client()
    return _USING_FALLBACK


def get_db():
    return _client()[os.environ.get("MONGODB_DB_NAME", "chronos_dev")]


def sessions_collection():
    return get_db()["sessions"]


def incident_logs_collection():  # used by Person C (RAG)
    return get_db()["incident_logs"]
