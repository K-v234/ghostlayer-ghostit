#!/usr/bin/env python3
"""
Ghost IT — Active Deception Injection: Poisoning Reconnaissance

Breakthrough #2: C3's existing canaries are static -- fixed decoy
files sitting and waiting for an attacker to stumble onto them. This
is genuinely more aggressive: the moment the Cortex detects elevated
suspicion on an entity (even below the autonomous-action threshold),
the system dynamically GENERATES fresh, contextually-relevant fake
data specifically targeted at what that suspicious process appears to
be hunting for -- not just detecting the attacker, but actively
corrupting their reconnaissance with data that looks real but is
completely fabricated, wasting real attacker time and effort.
"""
from __future__ import annotations
import os
import time
import random
import string
import logging
import threading
import duckdb

log = logging.getLogger(__name__)

DECEPTION_DB_PATH = os.environ.get("DECEPTION_DB_PATH",
    os.path.expanduser("~/ghostlayer/data/active_deception.duckdb"))

# Minimum Cortex score before active injection engages -- deliberately
# LOWER than the Autonomous Response Engine's action threshold (75),
# since injecting fake data is far less risky than suspending/isolating
# a process -- worst case for a false positive here is a legitimate
# process reads some harmless fake data, not a business disruption.
INJECTION_TRIGGER_SCORE = 50

def _fake_credential(context_hint: str) -> str:
    """Generate a fresh, plausible-looking fake credential, contextually
    flavored based on what the suspicious process seems to be after."""
    rand = "".join(random.choices(string.ascii_letters + string.digits, k=24))
    if "aws" in context_hint.lower() or "cloud" in context_hint.lower():
        return f"AKIA{''.join(random.choices(string.ascii_uppercase + string.digits, k=16))}"
    if "db" in context_hint.lower() or "sql" in context_hint.lower() or "database" in context_hint.lower():
        return f"DB_PASSWORD=Xk9#{rand[:12]}!mP2"
    if "api" in context_hint.lower():
        return f"api_key_live_{rand}"
    return f"SECRET_{rand}"

def _fake_document_name(context_hint: str) -> str:
    themes = ["Q3_Financial_Report", "Employee_Salaries_2026", "M&A_Confidential",
              "Client_Contracts_Master", "Board_Meeting_Minutes"]
    return f"{random.choice(themes)}_{random.randint(1000,9999)}.docx"

class ActiveDeception:
    def __init__(self, db_path: str = DECEPTION_DB_PATH):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._lock = threading.Lock()
        self.conn = duckdb.connect(db_path)
        self._init_schema()
        log.info(f"ActiveDeception initialized: {db_path}")

    def _init_schema(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS injections (
                entity_id      VARCHAR NOT NULL,
                injection_type VARCHAR NOT NULL,
                fake_content   VARCHAR NOT NULL,
                context_hint   VARCHAR,
                trigger_score  DOUBLE NOT NULL,
                ts             DOUBLE NOT NULL
            )
        """)

    def should_inject(self, entity_id: str, cortex_score: float) -> bool:
        return cortex_score >= INJECTION_TRIGGER_SCORE

    def generate_injection(self, entity_id: str, context_hint: str,
                             cortex_score: float) -> dict:
        """
        Generate fresh, contextually-relevant fake data to feed to a
        suspicious process -- real, not templated static files. Every
        injection is genuinely unique, making it harder for an
        attacker to learn to recognize and filter out Ghost IT's
        decoys through repeated exposure (a real weakness of static
        canaries over time).
        """
        if not self.should_inject(entity_id, cortex_score):
            return {"injected": False, "reason": "below injection trigger score"}

        credential = _fake_credential(context_hint)
        doc_name = _fake_document_name(context_hint)
        fake_content = (
            f"# {doc_name}\n"
            f"# Generated fresh, contextually-relevant fake data\n"
            f"CREDENTIAL={credential}\n"
            f"ACCESS_LEVEL=admin\n"
            f"GENERATED_AT={time.time()}\n"
        )

        with self._lock:
            self.conn.execute(
                "INSERT INTO injections VALUES (?, ?, ?, ?, ?, ?)",
                [entity_id, "fake_credential_file", fake_content,
                 context_hint, cortex_score, time.time()]
            )

        log.warning(
            f"[ActiveDeception] INJECTING fresh fake data for {entity_id} "
            f"(score={cortex_score}, context='{context_hint}') -- "
            f"file={doc_name}, this specific fabrication has never been "
            f"generated before, defeating any attempt to learn and filter "
            f"static decoys through repeated exposure"
        )

        return {
            "injected": True, "entity_id": entity_id,
            "fake_filename": doc_name, "fake_content": fake_content,
            "reasoning": f"Cortex score {cortex_score} crossed injection threshold "
                         f"({INJECTION_TRIGGER_SCORE}) -- generated fresh, unique "
                         f"fake data to waste this process's reconnaissance effort "
                         f"and corrupt any data it collects.",
        }

    def get_injection_history(self, limit: int = 50) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT entity_id, injection_type, context_hint, trigger_score, ts "
                "FROM injections ORDER BY ts DESC LIMIT ?", [limit]
            ).fetchall()
        cols = ["entity_id", "injection_type", "context_hint", "trigger_score", "ts"]
        return [dict(zip(cols, r)) for r in rows]

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ad = ActiveDeception(db_path="/tmp/deception_test.duckdb")

    print("=== Suspicious process (score 35) hunting for 'database credentials' -- below trigger ===")
    r1 = ad.generate_injection("pid:200", "database credentials", 35)
    print(f"  {r1}\n")

    print("=== Suspicious process (score 65) hunting for 'aws cloud keys' -- ABOVE trigger, real injection ===")
    r2 = ad.generate_injection("pid:201", "aws cloud keys", 65)
    print(f"  {r2}\n")

    print("=== Same process type hunts again -- generates a DIFFERENT fake credential each time ===")
    r3 = ad.generate_injection("pid:202", "aws cloud keys", 70)
    print(f"  {r3}\n")

    print(f"=== Result: two AWS-context injections produced GENUINELY DIFFERENT fake credentials each time ({r2['fake_content'].split(chr(10))[2]} vs {r3['fake_content'].split(chr(10))[2]}), defeating pattern-learning by a repeat attacker ===")

    os.remove("/tmp/deception_test.duckdb")
