#!/usr/bin/env python3
"""
Start the AI SOC Platform (API + dashboard):

    python run.py                 -> http://127.0.0.1:8080
    python run.py --simulate      -> also stream simulated traffic and attacks
    python run.py analyze FILE    -> run detection over a log file
    python run.py train           -> train the ML anomaly model

The old run.py imported src.api.app.main, which required fastapi/uvicorn that
were missing from requirements.txt, and skipped logging setup.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.main import main  # noqa: E402

if __name__ == "__main__":
    main()
