"""Benchmark: arcanum key generation vs python-rsa (if installed)."""

from __future__ import annotations

import time
import statistics
import sys


def bench_arcanum(bits: int, rounds: int) -> list[float]:
    import arcanum

    times: list[float] = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        arcanum.newkeys(bits)
        times.append(time.perf_counter() - t0)
    return times


def bench_rsa(bits: int, rounds: int) -> list[float]:
    import rsa  # type: ignore[import-untyped]

    times: list[float] = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        rsa.newkeys(bits)
        times.append(time.perf_counter() - t0)
    return times


def report(name: str, times: list[float]) -> None:
    avg = statistics.mean(times)
    med = statistics.median(times)
    lo = min(times)
    hi = max(times)
    print(f"  {name:20s}  avg={avg:.3f}s  med={med:.3f}s  min={lo:.3f}s  max={hi:.3f}s")


def main() -> None:
    bits = int(sys.argv[1]) if len(sys.argv) > 1 else 1024
    rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 5

    print(f"Benchmarking {bits}-bit RSA key generation ({rounds} rounds)\n")

    print("arcanum:")
    arc_times = bench_arcanum(bits, rounds)
    report("arcanum", arc_times)

    try:
        print("\npython-rsa:")
        rsa_times = bench_rsa(bits, rounds)
        report("python-rsa", rsa_times)

        speedup = statistics.mean(rsa_times) / statistics.mean(arc_times)
        print(f"\n  arcanum is {speedup:.2f}x {'faster' if speedup > 1 else 'slower'} than python-rsa")
    except ImportError:
        print("\npython-rsa not installed — skipping comparison")
        print("  pip install rsa   # to enable comparison")


if __name__ == "__main__":
    main()
