#!/usr/bin/env python3
"""
Write simulated security telemetry (normal traffic + injected attacks) to a
JSON-lines file. Put it in the data/raw folder and the running platform
ingests it, or analyse it offline with `python run.py analyze <file>`.

    python scripts/generate_logs.py --count 2000 --attacks 10 --output data/raw/sample.jsonl

Each line has a "_truth" field (malicious / scenario) for evaluation; the
platform ignores it for detection.
"""
import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from src.simulation.traffic import generate_dataset  # noqa: E402


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--count", type=int, default=2000, help="normal events")
    p.add_argument("--attacks", type=int, default=10, help="attack scenarios to inject")
    p.add_argument("--rate", type=float, default=5.0, help="events per second (sets the time span)")
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--output", default="data/raw/sample.jsonl",
                   help="the running platform watches data/raw/*.jsonl (or <SOC_DATA_DIR>/raw)")
    args = p.parse_args()

    events = generate_dataset(args.count, args.attacks, seed=args.seed, rate=args.rate)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    scenarios = Counter(e["_truth"]["scenario"] for e in events if e["_truth"]["malicious"])
    print(f"Wrote {len(events)} events to {out}")
    print(f"Attack events by scenario: {dict(scenarios)}")


if __name__ == "__main__":
    main()
