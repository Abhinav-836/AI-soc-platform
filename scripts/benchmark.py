#!/usr/bin/env python3
"""
Measure detection throughput and latency (whole pipeline: normalize, intel,
rules, Sigma, ML, correlation, storage) on simulated traffic.

    python scripts/benchmark.py --events 20000
"""
import argparse
import asyncio
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))


async def run(n: int):
    os.environ.setdefault("SOC_DATA_DIR", tempfile.mkdtemp(prefix="soc-bench-"))
    from src.main import SOCPlatform
    from src.simulation.traffic import generate_dataset

    platform = SOCPlatform(db_path=":memory:")
    platform.intel.load()
    if not platform.ml.load():
        await platform.ml.retrain()
    await platform.detection.start()
    events = generate_dataset(n_normal=n, n_attacks=max(1, n // 500), seed=1)
    start = time.perf_counter()
    for e in events:
        await platform.ingestion.process(e)
    elapsed = time.perf_counter() - start
    stats = platform.detection.get_stats()
    await platform.detection.stop()
    print(f"{len(events)} events in {elapsed:.2f}s -> {len(events) / elapsed:,.0f} events/s")
    print(f"per-event latency: {stats['latency_ms']}")
    print(f"alerts created: {stats['alerts_created']}, updated: {stats['alerts_updated']}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--events", type=int, default=20000)
    asyncio.run(run(p.parse_args().events))
