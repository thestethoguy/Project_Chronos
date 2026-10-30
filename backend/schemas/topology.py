"""Pydantic contract for an uploaded network_topology.json (Guide Section 7.3, Step 1).
Compatible with both Pydantic v1 (local pure-Python venv) and Pydantic v2 (Render cloud).
"""
from typing import Any, Literal

import pydantic
from pydantic import BaseModel, Field

_HAS_V2 = hasattr(pydantic, "field_validator")


class _CompatModel(BaseModel):
    def model_dump(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        if hasattr(super(), "model_dump"):
            return super().model_dump(*args, **kwargs)  # type: ignore[misc]
        return self.dict(*args, **kwargs)


class TopologyDevice(_CompatModel):
    id: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=128)
    ip: str
    subnet: Literal["public_dmz", "internal_core"]
    ports: list[int] = []
    os: str
    cves: list[str] = []


class TopologyConnection(_CompatModel):
    source: str
    target: str
    type: str


def _validate_devices_list(devices: list[TopologyDevice]) -> list[TopologyDevice]:
    ids = [d.id for d in devices]
    if len(ids) != len(set(ids)):
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        raise ValueError(f"Duplicate device ids: {dupes}")
    return devices


def _validate_connections_list(
    connections: list[TopologyConnection], devices: list[TopologyDevice]
) -> list[TopologyConnection]:
    known = {d.id for d in devices}
    for conn in connections:
        if conn.source not in known or conn.target not in known:
            raise ValueError(
                f"Connection references unknown device id: {conn.source} -> {conn.target}"
            )
    return connections


if _HAS_V2:
    from pydantic import field_validator

    class NetworkTopologyFile(_CompatModel):
        devices: list[TopologyDevice]
        connections: list[TopologyConnection]

        @field_validator("devices")
        @classmethod
        def _check_devices(cls, v: list[TopologyDevice]) -> list[TopologyDevice]:
            return _validate_devices_list(v)

        @field_validator("connections")
        @classmethod
        def _check_connections(
            cls, v: list[TopologyConnection], info: Any
        ) -> list[TopologyConnection]:
            devices = (info.data or {}).get("devices", [])
            return _validate_connections_list(v, devices)

else:
    from pydantic import validator

    class NetworkTopologyFile(_CompatModel):  # type: ignore[no-redef]
        devices: list[TopologyDevice]
        connections: list[TopologyConnection]

        @validator("devices")
        def _check_devices(cls, v: list[TopologyDevice]) -> list[TopologyDevice]:
            return _validate_devices_list(v)

        @validator("connections")
        def _check_connections(
            cls, v: list[TopologyConnection], values: dict[str, Any]
        ) -> list[TopologyConnection]:
            devices = values.get("devices", [])
            return _validate_connections_list(v, devices)

