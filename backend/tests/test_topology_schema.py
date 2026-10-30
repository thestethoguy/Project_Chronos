import pytest
from pydantic import ValidationError

from backend.schemas.topology import NetworkTopologyFile

DEV = {"name": "x", "ip": "10.0.0.1", "subnet": "internal_core", "ports": [22], "os": "linux"}


def mk(ids):
    return [{"id": i, **DEV} for i in ids]


def test_valid():
    t = NetworkTopologyFile(
        devices=mk(["a", "b"]), connections=[{"source": "a", "target": "b", "type": "T"}]
    )
    assert len(t.devices) == 2 and t.devices[0].cves == []


def test_unknown_device_rejected():
    with pytest.raises(ValidationError):
        NetworkTopologyFile(
            devices=mk(["a"]), connections=[{"source": "a", "target": "zzz", "type": "T"}]
        )


def test_duplicate_ids_rejected():
    with pytest.raises(ValidationError):
        NetworkTopologyFile(devices=mk(["a", "a"]), connections=[])


def test_bad_subnet_rejected():
    bad = {"id": "a", **{**DEV, "subnet": "nope"}}
    with pytest.raises(ValidationError):
        NetworkTopologyFile(devices=[bad], connections=[])
