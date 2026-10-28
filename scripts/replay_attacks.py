#!/usr/bin/env python3
"""
Send simulated attack scenarios to a running platform over the REST API
(the same path a real log shipper would use).

    python scripts/replay_attacks.py --scenario brute_force
    python scripts/replay_attacks.py --scenario all --api-url http://127.0.0.1:8080 --api-key KEY

Events keep their relative timing (use --speed 10 to replay 10x faster).
The ground-truth label is stripped by the API, so detection is a blind test.
"""
import argparse
import json
import os
import sys
import time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from src.core.time_utils import iso  # noqa: E402
from src.simulation.traffic import SCENARIOS, TrafficGenerator  # noqa: E402


def post(url: str, payload, api_key: str):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **({"X-API-Key": api_key} if api_key else {})})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--scenario", default="all", choices=["all", *SCENARIOS])
    p.add_argument("--api-url", default="http://127.0.0.1:8080")
    p.add_argument("--api-key", default=os.getenv("SOC_API_KEY", ""))
    p.add_argument("--speed", type=float, default=1.0, help="replay speed multiplier")
    args = p.parse_args()

    gen = TrafficGenerator()
    for name in (SCENARIOS if args.scenario == "all" else [args.scenario]):
        _, sid, steps = gen.attack(name)
        print(f"\n▶ {name} ({sid}): {len(steps)} events")
        start, alerts = time.time(), set()
        for delay, event in steps:
            wait = start + delay / args.speed - time.time()
            if wait > 0:
                time.sleep(wait)
            event.pop("_truth", None)
            event["@timestamp"] = iso()
            result = post(f"{args.api_url}/api/v1/ingest", event, args.api_key)
            alerts.update(result.get("alert_ids", []))
        print(f"  alerts raised/updated: {sorted(alerts) or 'none'}")


if __name__ == "__main__":
    main()
