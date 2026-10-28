#!/usr/bin/env python3
"""
Train (and evaluate) the anomaly model.

    python scripts/train_models.py                       # learn from simulated normal traffic
    python scripts/train_models.py --input normal.jsonl  # learn YOUR network's normal

The old script imported src.utils.config_loader, which doesn't exist, and
crashed immediately.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from src.core.config_loader import ConfigLoader  # noqa: E402
from src.ml.training import ModelTrainer, model_path  # noqa: E402


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--input", help="JSONL or plain log file of mostly normal events")
    p.add_argument("--config", default=None)
    args = p.parse_args()
    meta = ModelTrainer(ConfigLoader(args.config)).train_and_evaluate(args.input)
    print(json.dumps(meta, indent=2, default=str))
    print(f"\nSaved to {model_path()} - restart the platform or use Detection -> Retrain to load it.")


if __name__ == "__main__":
    main()
