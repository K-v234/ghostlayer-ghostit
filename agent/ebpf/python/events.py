"""
Ghost IT — Event Schema
Type-safe Python mirror of the C ghost_event struct.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from enum import IntEnum
from typing import Optional
import json


class EventType(IntEnum):
    EXEC    = 1
    OPEN    = 2
    CONNECT = 3
    CLONE   = 4
    UNLINK  = 5


@dataclass
class GhostEvent:
    """Structured kernel event from the eBPF agent."""
    ts:   int           # Nanoseconds since boot
    pid:  int
    ppid: int
    uid:  int
    gid:  int
    comm: str           # Process name
    type: str           # EventType string

    # Optional fields — present depending on event type
    file:        Optional[str] = None
    args:        Optional[str] = None
    flags:       Optional[int] = None
    daddr:       Optional[str] = None
    dport:       Optional[int] = None
    family:      Optional[int] = None
    clone_flags: Optional[int] = None

    @classmethod
    def from_dict(cls, d: dict) -> GhostEvent:
        valid = {k for k in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in valid})

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}

    def to_json(self) -> str:
        return json.dumps(self.to_dict())
