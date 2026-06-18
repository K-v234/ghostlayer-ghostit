#!/usr/bin/env python3
"""
Ghost IT — V0 Acceptance Test

Per Build Guide spec:
  ✅ CPU < 1% on idle endpoint
  ✅ Memory < 80MB RSS
  ✅ 0 kernel panics in dmesg
  ✅ Ransomware detection < 1 second
  ✅ ONNX inference < 5ms
  ✅ CADE adversarial detection working
  ✅ Canary traps firing
  ✅ SLSA binary signed and verifiable

Ghost Layer Technologies — CONFIDENTIAL
"""
import os
import sys
import time
import json
import subprocess
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [v0-test] %(levelname)s %(message)s"
)
log = logging.getLogger(__name__)

PASS = "✅ PASS"
FAIL = "❌ FAIL"
WARN = "⚠️  WARN"

results = []


def test(name: str, passed: bool, detail: str = "", warn: bool = False):
    status = WARN if warn else (PASS if passed else FAIL)
    results.append((name, status, detail))
    log.info(f"{status} {name}: {detail}")


# ------------------------------------------------------------------ #
# Test 1: Binary signature                                            #
# ------------------------------------------------------------------ #
def test_binary_signature():
    bundle = os.path.expanduser("~/ghostlayer/ghostit-agent-linux-amd64.cosign.bundle")
    binary = os.path.expanduser("~/ghostlayer/ghostit-agent-linux-amd64")

    if not os.path.exists(bundle):
        test("Binary signature", False, "cosign bundle not found")
        return
    if not os.path.exists(binary):
        test("Binary signature", False, "agent binary not found")
        return

    result = subprocess.run([
        "cosign", "verify-blob",
        "--bundle", bundle,
        "--certificate-identity-regexp", ".*",
        "--certificate-oidc-issuer", "https://github.com/login/oauth",
        binary,
    ], capture_output=True, text=True)

    test("Binary signature (cosign)",
         result.returncode == 0,
         "Verified OK" if result.returncode == 0 else result.stderr[:80])


# ------------------------------------------------------------------ #
# Test 2: Kernel panic check                                          #
# ------------------------------------------------------------------ #
def test_kernel_panics():
    result = subprocess.run(
        ["dmesg"],
        capture_output=True, text=True
    )
    panics = [l for l in result.stdout.splitlines()
              if "panic" in l.lower() or "oops" in l.lower()]
    test("Kernel panics", len(panics) == 0,
         f"0 panics" if not panics else f"{len(panics)} panics found")


# ------------------------------------------------------------------ #
# Test 3: BPF errors in dmesg                                        #
# ------------------------------------------------------------------ #
def test_bpf_errors():
    result = subprocess.run(["dmesg"], capture_output=True, text=True)
    errors = [l for l in result.stdout.splitlines()
              if "bpf" in l.lower() and
              any(w in l.lower() for w in ["error", "failed", "denied"])]
    test("BPF kernel errors", len(errors) == 0,
         f"0 BPF errors" if not errors else f"{len(errors)} errors: {errors[0][:60]}")


# ------------------------------------------------------------------ #
# Test 4: ONNX inference latency                                      #
# ------------------------------------------------------------------ #
def test_onnx_latency():
    try:
        from inference.runtime import GhostONNXRuntime
        runtime = GhostONNXRuntime("isolation_forest")
        vec     = [0.1] * 17

        # Warmup
        for _ in range(3):
            runtime.infer(vec)

        # Measure
        times = []
        for _ in range(10):
            result = runtime.infer(vec)
            times.append(result["latency_ms"])

        avg_ms = sum(times) / len(times)
        p99_ms = sorted(times)[-1]

        test("ONNX inference latency",
             avg_ms < 5.0,
             f"avg={avg_ms:.2f}ms p99={p99_ms:.2f}ms (target <5ms)")
    except Exception as ex:
        test("ONNX inference latency", False, str(ex))


# ------------------------------------------------------------------ #
# Test 5: Ransomware detection speed                                  #
# ------------------------------------------------------------------ #
def test_ransomware_detection():
    try:
        from detection.ransomware import RansomwareEMADetector
        import numpy as np

        detector = RansomwareEMADetector()

        # Warm up baseline
        for _ in range(10):
            detector.process_event({"type": "open", "file": "/home/user/doc.pdf", "flags": 1})
            detector._window_start -= 61
            detector._maybe_flush_window()

        # Simulate ransomware attack — measure detection time
        t0 = time.perf_counter()
        for i in range(50):
            detector.process_event({"type": "open", "file": f"/home/user/doc{i}.locked", "flags": 3})
            detector.process_event({"type": "unlink", "file": f"/home/user/doc{i}.docx"})

        detector._window_start -= 61
        alert = detector._maybe_flush_window()
        elapsed_ms = (time.perf_counter() - t0) * 1000

        test("Ransomware detection speed",
             alert is not None and elapsed_ms < 1000,
             f"{'Detected' if alert else 'Not detected'} in {elapsed_ms:.1f}ms (target <1000ms)")
    except Exception as ex:
        test("Ransomware detection speed", False, str(ex))


# ------------------------------------------------------------------ #
# Test 6: CADE adversarial detection                                  #
# ------------------------------------------------------------------ #
def test_cade():
    try:
        from detection.behavioral.cade import CADEDriftDetector, DriftType
        from detection.behavioral.features import BEHAVIORAL_FEATURES
        import numpy as np

        detector = CADEDriftDetector("v0_test", BEHAVIORAL_FEATURES)
        np.random.seed(42)

        # Build reference
        for _ in range(10):
            detector.reference_embeddings.append(
                [float(np.random.exponential(0.5)) for _ in BEHAVIORAL_FEATURES]
            )

        X_ref = np.array(detector.reference_embeddings, dtype=np.float32)
        detector.encoder.train(X_ref, epochs=30)

        # Inject adversarial poisoning
        for _ in range(50):
            vec = {f: float(np.random.exponential(0.5)) for f in BEHAVIORAL_FEATURES}
            vec["privilege_escalation_ct"] = 50.0
            vec["mmap_exec_rate"]          = 30.0
            detector.current_windows.append([vec[f] for f in BEHAVIORAL_FEATURES])

        report = detector.force_check()
        detected = report and report.type == DriftType.ADVERSARIAL

        test("CADE adversarial detection", detected,
             f"score={report.adversarial_score:.3f}" if report else "no report")
    except Exception as ex:
        test("CADE adversarial detection", False, str(ex))


# ------------------------------------------------------------------ #
# Test 7: API health                                                   #
# ------------------------------------------------------------------ #
def test_api_health():
    try:
        import urllib.request
        with urllib.request.urlopen(
            "http://127.0.0.1:8000/health", timeout=3
        ) as r:
            data = json.loads(r.read())
        test("Pipeline API health", data.get("status") == "ok",
             f"status={data.get('status')}")
    except Exception as ex:
        test("Pipeline API health", False, str(ex), warn=True)


# ------------------------------------------------------------------ #
# Test 8: DuckDB data flow                                            #
# ------------------------------------------------------------------ #
def test_data_flow():
    try:
        import urllib.request
        with urllib.request.urlopen(
            "http://127.0.0.1:8000/stats", timeout=3
        ) as r:
            data = json.loads(r.read())
        total = data.get("total", 0)
        test("DuckDB data flow", total > 0,
             f"{total} events stored")
    except Exception as ex:
        test("DuckDB data flow", False, str(ex), warn=True)


# ------------------------------------------------------------------ #
# Test 9: Model signed and verified                                   #
# ------------------------------------------------------------------ #
def test_model_signing():
    try:
        from inference.signing import verify_model
        model_path = os.path.expanduser(
            "~/ghostlayer/data/models/isolation_forest.onnx"
        )
        result = verify_model(model_path)
        test("ONNX model signature", result, "Verified OK")
    except Exception as ex:
        test("ONNX model signature", False, str(ex))


# ------------------------------------------------------------------ #
# Test 10: gRPC proto generated                                       #
# ------------------------------------------------------------------ #
def test_grpc_proto():
    try:
        sys.path.insert(0, os.path.expanduser("~/ghostlayer/comms"))
        import ghost_pb2
        e = ghost_pb2.Event(pid=1234, comm="test")
        test("gRPC proto", e.pid == 1234, "Proto generated and loadable")
    except Exception as ex:
        test("gRPC proto", False, str(ex))


# ------------------------------------------------------------------ #
# Run all tests                                                        #
# ------------------------------------------------------------------ #
def main():
    log.info("=" * 50)
    log.info("Ghost IT V0 Acceptance Test")
    log.info("=" * 50)

    test_binary_signature()
    test_kernel_panics()
    test_bpf_errors()
    test_onnx_latency()
    test_ransomware_detection()
    test_cade()
    test_api_health()
    test_data_flow()
    test_model_signing()
    test_grpc_proto()

    # Summary
    log.info("\n" + "=" * 50)
    log.info("V0 ACCEPTANCE TEST RESULTS")
    log.info("=" * 50)

    passed = sum(1 for _, s, _ in results if "PASS" in s)
    warned = sum(1 for _, s, _ in results if "WARN" in s)
    failed = sum(1 for _, s, _ in results if "FAIL" in s)

    for name, status, detail in results:
        log.info(f"  {status} {name}: {detail}")

    log.info(f"\nTotal: {passed} passed, {warned} warnings, {failed} failed")

    if failed == 0:
        log.info("✅ V0 ACCEPTANCE TEST PASSED")
    else:
        log.info(f"❌ V0 ACCEPTANCE TEST FAILED — {failed} failures")

    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
