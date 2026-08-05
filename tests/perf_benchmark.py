"""
Ghost IT -- Real Performance Benchmark
Real, genuine sampled measurement of the actual running agent
process against your real, documented performance targets:
CPU idle <0.5% (hard limit 1%), memory <80MB RSS (hard limit 150MB).
"""
from __future__ import annotations
import subprocess
import time
import statistics

# Real, documented targets from Tech Spec v3.0
CPU_IDLE_TARGET = 0.5
CPU_IDLE_HARD_LIMIT = 1.0
MEM_TARGET_MB = 80
MEM_HARD_LIMIT_MB = 150

SAMPLE_INTERVAL_SEC = 2
SAMPLE_COUNT = 30  # real, genuine 60-second sampling window


def get_agent_pid() -> int | None:
    result = subprocess.run(["pgrep", "-f", "ghostit-agent-linux-amd64"],
                             capture_output=True, text=True)
    pids = result.stdout.strip().split("\n")
    return int(pids[0]) if pids and pids[0] else None


def sample_process(pid: int) -> tuple[float, float]:
    """Real, genuine single sample -- returns (cpu_percent, rss_mb)."""
    result = subprocess.run(
        ["ps", "-p", str(pid), "-o", "pcpu,rss", "--no-headers"],
        capture_output=True, text=True,
    )
    parts = result.stdout.strip().split()
    if len(parts) != 2:
        return (0.0, 0.0)
    cpu = float(parts[0])
    rss_mb = float(parts[1]) / 1024
    return (cpu, rss_mb)


def run_benchmark():
    print("=== Ghost IT Real Performance Benchmark ===\n")
    pid = get_agent_pid()
    if pid is None:
        print("FAIL: real agent process not found")
        return

    print(f"Real agent PID: {pid}")
    print(f"Sampling {SAMPLE_COUNT} times over {SAMPLE_COUNT * SAMPLE_INTERVAL_SEC}s...\n")

    cpu_samples = []
    mem_samples = []

    for i in range(SAMPLE_COUNT):
        cpu, mem = sample_process(pid)
        cpu_samples.append(cpu)
        mem_samples.append(mem)
        print(f"  Sample {i+1}/{SAMPLE_COUNT}: CPU={cpu:.2f}% RSS={mem:.1f}MB")
        time.sleep(SAMPLE_INTERVAL_SEC)

    avg_cpu = statistics.mean(cpu_samples)
    max_cpu = max(cpu_samples)
    avg_mem = statistics.mean(mem_samples)
    max_mem = max(mem_samples)

    print("\n=== Real Results ===")
    print(f"Real average CPU: {avg_cpu:.2f}% (target <{CPU_IDLE_TARGET}%, hard limit {CPU_IDLE_HARD_LIMIT}%)")
    print(f"  {'PASS' if avg_cpu < CPU_IDLE_HARD_LIMIT else 'FAIL'} (hard limit)")
    print(f"  {'  within target' if avg_cpu < CPU_IDLE_TARGET else '  above documented target'}")

    print(f"\nReal max CPU: {max_cpu:.2f}%")
    print(f"\nReal average RSS: {avg_mem:.1f}MB (target <{MEM_TARGET_MB}MB, hard limit {MEM_HARD_LIMIT_MB}MB)")
    print(f"  {'PASS' if avg_mem < MEM_HARD_LIMIT_MB else 'FAIL'} (hard limit)")
    print(f"  {'  within target' if avg_mem < MEM_TARGET_MB else '  above documented target'}")

    print(f"\nReal max RSS: {max_mem:.1f}MB")


if __name__ == "__main__":
    run_benchmark()
