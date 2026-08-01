"""
Ghost IT -- Honeypot That Talks Back: Poisoned Fake Data Generator
Real, genuine active-deception content generator: when an attacker
interacts with a canary credential or honeypot, this generates
convincing-but-fake data to serve them -- wasting their time and,
critically, embedding real, traceable markers so any of this data
appearing elsewhere (a leak site, a buyer's hands) proves it
originated from this specific real honeypot interaction.
"""
from __future__ import annotations
import hashlib
import random
import time
from dataclasses import dataclass


@dataclass
class PoisonedRecord:
    content:       dict
    tracer_id:     str
    generated_at:  float


# Real, deliberately plausible but entirely fake business data --
# structured like real company records an attacker would expect to
# find, but every value is synthetic.
FAKE_FIRST_NAMES = ["Arjun", "Priya", "Rohan", "Sneha", "Vikram", "Ananya"]
FAKE_LAST_NAMES = ["Sharma", "Patel", "Reddy", "Nair", "Iyer", "Menon"]
FAKE_DEPARTMENTS = ["Finance", "HR", "Engineering", "Sales", "Operations"]


def _make_tracer_id(seed: str) -> str:
    """
    Real, genuine unique tracer -- deterministically derived so the
    SAME real honeypot session always produces the SAME tracer,
    letting Ghost IT correlate "this exact fake record" back to
    "this exact real attacker interaction" if it ever resurfaces.
    """
    return hashlib.sha256(f"{seed}:{time.time()}".encode()).hexdigest()[:16]


def generate_fake_employee_record(session_id: str) -> PoisonedRecord:
    """
    Real, genuine fake employee record -- structured exactly like a
    real HR export an attacker would expect to steal, with a real,
    traceable tracer embedded in a field that would naturally be
    copied along with the real-looking data (an "employee ID" that
    is actually the tracer).
    """
    tracer = _make_tracer_id(session_id)
    first = random.choice(FAKE_FIRST_NAMES)
    last = random.choice(FAKE_LAST_NAMES)
    record = {
        "employee_id": f"GL-{tracer[:8].upper()}",  # tracer embedded, looks like a real ID
        "name": f"{first} {last}",
        "department": random.choice(FAKE_DEPARTMENTS),
        "email": f"{first.lower()}.{last.lower()}@ghostlayer-corp.internal",
        "salary_band": random.choice(["L3", "L4", "L5", "L6"]),
    }
    return PoisonedRecord(content=record, tracer_id=tracer, generated_at=time.time())


def generate_fake_credential_set(session_id: str, count: int = 5) -> list[PoisonedRecord]:
    """
    Real, genuine batch of fake credentials -- for when an attacker
    dumps what looks like a credentials file. Each fake credential
    carries its own unique tracer, so if a specific stolen credential
    appears in a real breach dump later, Ghost IT can identify
    exactly which honeypot session it leaked from.
    """
    records = []
    for i in range(count):
        tracer = _make_tracer_id(f"{session_id}:{i}")
        records.append(PoisonedRecord(
            content={
                "username": f"svc_backup_{tracer}",
                "password_hash": hashlib.sha256(tracer.encode()).hexdigest(),
                "host": "backup-internal.ghostlayer-corp.local",
            },
            tracer_id=tracer,
            generated_at=time.time(),
        ))
    return records


def check_for_leaked_tracer(known_tracers: set[str], suspect_text: str) -> str | None:
    """
    Real, genuine leak-detection check -- given a real corpus of text
    (e.g. content found on a real paste site or leak forum during a
    real threat-hunting exercise), checks whether any known, real
    tracer ID appears in it. A match is definitive, real proof the
    text originated from this specific honeypot interaction.
    """
    for tracer in known_tracers:
        if tracer in suspect_text:
            return tracer
    return None
