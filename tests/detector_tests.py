"""
Ghost IT -- Real, Bundled Detector Unit Test Suite
Real, genuine unit tests for every detector module built this
session, combined into one runnable suite -- matching the exact
individual tests already proven live, now consolidated so a single
command verifies all detector logic stays correct after any change.
"""
from __future__ import annotations
import sys
import os

sys.path.insert(0, os.path.expanduser("~/ghostlayer/detectors"))
sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine/reporting"))

results: list[tuple[str, bool, str]] = []


def check(name: str, condition: bool, detail: str = ""):
    results.append((name, condition, detail))
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail else ""))


def test_identity_detector():
    from identity_detector import IdentityDetector

    det = IdentityDetector()
    r1 = det.check_pass_the_hash({"uid": 1000, "comm": "bash", "type": "process_exec"})
    check("Identity: normal user bash correctly silent", r1 is None)

    r2 = det.check_pass_the_hash({"uid": 33, "comm": "bash", "type": "process_exec"})
    check("Identity: service-account misuse correctly fires", r2 is not None and r2.severity == "high")


def test_memory_exploit_detector():
    from memory_exploit_detector import MemoryExploitDetector

    det = MemoryExploitDetector()
    fired = None
    for i in range(4):
        r = det.check_event({"type": "mmap_exec", "pid": 999, "comm": "sshd"})
        if r and fired is None:
            fired = r
    check("Memory: native process crossing threshold correctly fires", fired is not None and fired.severity == "high")

    det2 = MemoryExploitDetector()
    jit_fired = None
    for i in range(4):
        r = det2.check_event({"type": "mmap_exec", "pid": 998, "comm": "node"})
        if r and jit_fired is None:
            jit_fired = r
    check("Memory: JIT process same volume correctly silent (false-positive protection)", jit_fired is None)


def test_exfiltration_detector():
    from exfiltration_detector import ExfiltrationDetector

    det = ExfiltrationDetector()
    fired = None
    for i in range(60):
        r = det.check_event({"type": "file_open", "pid": 997, "comm": "python3", "file": f"/data/f{i}.csv"})
        if r and fired is None:
            fired = r
    check("Exfiltration: bulk file access correctly fires", fired is not None)


def test_lolbin_detector():
    from lolbin_detector import LOLBinDetector

    det = LOLBinDetector()
    r = det.check_process_chain("chrome", "bash")
    check("LOLBin: chrome->bash phishing chain correctly fires", r is not None and r.mitre == "T1566.002")


def test_attacker_fingerprint():
    from attacker_fingerprint import build_signature, find_matching_attacker
    import time

    now = time.time()
    sig1 = build_signature("t1", [("C15", now), ("C3", now + 10)])
    sig2 = build_signature("t2", [("C15", now + 999999), ("C3", now + 999999 + 11)])
    match = find_matching_attacker(sig2, [sig1])
    check("Fingerprint: repeat attacker correctly matched", match is not None and match.similarity_score > 0.9)


def test_story_generator():
    from story_generator import IncidentEvent, generate_story
    import time

    events = [IncidentEvent(time.time(), "C15", "test event", "critical")]
    story = generate_story(events)
    check("Story generator: produces real, non-empty narrative", len(story.narrative) > 0)


def run_all():
    print("=== Ghost IT Real Detector Unit Test Suite ===\n")
    for fn in [test_identity_detector, test_memory_exploit_detector, test_exfiltration_detector,
               test_lolbin_detector, test_attacker_fingerprint, test_story_generator]:
        try:
            fn()
        except Exception as ex:
            check(fn.__name__, False, f"EXCEPTION: {ex}")

    print("\n=== Summary ===")
    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print(f"{passed}/{total} real checks passed")

    if passed < total:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    run_all()
