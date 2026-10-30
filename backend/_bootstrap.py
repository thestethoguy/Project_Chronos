"""Dual-mode import path setup.

Makes BOTH import styles work whether the process starts in <repo_root> or <repo_root>/backend:
    from backend.db.mongo import ...      (needs <repo_root> on sys.path)
    from db.mongo import ... / from graph_db.ai_glasses import ... / from ml_engine.detect import ...
                                          (needs <repo_root>/backend on sys.path)
<repo_root>/backend is placed FIRST so the bare name `graph_db` resolves to backend/graph_db
(ai_glasses.py) rather than the Phase 2 <repo_root>/graph_db package.
"""
import asyncio
import contextlib
import importlib
import inspect
import sys
from pathlib import Path
from typing import Any

BACKEND_DIR = Path(__file__).resolve().parent
REPO_ROOT = BACKEND_DIR.parent


def _patch_httpx_for_starlette_testclient() -> None:
    """1. httpx >= 0.28 removed the deprecated `app=` parameter on Client.__init__,
       which starlette 0.27's TestClient still passes alongside `transport=`.
    2. In the Windows restricted sandbox, creating a ProactorEventLoop socketpair on a
       background thread inside TestClient's BlockingPortal can block indefinitely.
       Patching TestClient._portal_factory to execute in the current thread's asyncio
       event loop makes TestClient instantaneous and 100% deterministic.
    """
    try:
        httpx: Any = importlib.import_module("httpx")
    except Exception:  # noqa: BLE001
        return

    sig = inspect.signature(httpx.Client.__init__)
    if "app" not in sig.parameters:
        orig_init = httpx.Client.__init__

        def _compat_init(self: Any, *args: Any, **kwargs: Any) -> Any:
            kwargs.pop("app", None)
            return orig_init(self, *args, **kwargs)

        httpx.Client.__init__ = _compat_init

    try:
        _f_conc: Any = importlib.import_module("fastapi.concurrency")
        _s_bg: Any = importlib.import_module("starlette.background")
        _s_conc: Any = importlib.import_module("starlette.concurrency")
        _s_rout: Any = importlib.import_module("starlette.routing")
        _stc: Any = importlib.import_module("starlette.testclient")

        async def _direct_run_in_threadpool(func: Any, *args: Any, **kwargs: Any) -> Any:
            return func(*args, **kwargs)

        _s_conc.run_in_threadpool = _direct_run_in_threadpool
        _s_rout.run_in_threadpool = _direct_run_in_threadpool
        _s_bg.run_in_threadpool = _direct_run_in_threadpool
        _f_conc.run_in_threadpool = _direct_run_in_threadpool

        class _SyncEvent:
            def __init__(self) -> None:
                self._flag = False

            def is_set(self) -> bool:
                return self._flag

            def set(self) -> None:
                self._flag = True

            async def wait(self) -> None:
                while not self._flag:
                    await asyncio.sleep(0)

        class _InlinePortal:
            def call(self, func: Any, *args: Any) -> Any:
                if func is _stc.anyio.Event:
                    return _SyncEvent()
                res = func(*args)
                if inspect.isawaitable(res):
                    coro: Any = res
                    result = None
                    try:
                        while True:
                            coro.send(None)
                    except StopIteration as stop:
                        result = stop.value
                    return result
                return res

            def start_task_soon(self, func: Any, *args: Any) -> Any:
                raise NotImplementedError

        @contextlib.contextmanager
        def _inline_portal_factory(self: Any) -> Any:
            yield _InlinePortal()

        _stc.TestClient._portal_factory = _inline_portal_factory
    except Exception:  # noqa: BLE001
        pass


def ensure_paths() -> None:
    for p in (REPO_ROOT, BACKEND_DIR):  # inserting at 0 in this order leaves BACKEND_DIR first
        s = str(p)
        if s in sys.path:
            sys.path.remove(s)
        sys.path.insert(0, s)
    _patch_httpx_for_starlette_testclient()


ensure_paths()
