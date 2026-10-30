import mongomock
import pytest

from backend.db import session_store as s


@pytest.fixture(autouse=True)
def fake_mongo():
    col = mongomock.MongoClient()["t"]["sessions"]
    s.set_collection_factory(lambda: col)
    yield


def test_empty_creates_idle():
    assert s.get_current_session()["status"] == "idle"


def test_second_start_conflicts():
    assert s.try_start_session() is not None
    assert s.try_start_session() is None  # -> 409


def test_update_and_persist():
    s.try_start_session()
    s.update_current_session(status="completed", action_taken="done")
    cur = s.get_current_session()
    assert cur["status"] == "completed" and cur["cycles_run"] == 1
    assert s.try_start_session()["cycles_run"] == 2


def test_reset_preserves_cycles():
    s.try_start_session()
    assert s.reset_session()["cycles_run"] == 1
    assert s.get_current_session()["status"] == "idle"
