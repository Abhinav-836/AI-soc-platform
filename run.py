#!/usr/bin/env python3
"""
Run script for AI SOC Platform.
"""

import sys
import os
import asyncio

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.api.app import main

if __name__ == "__main__":
    asyncio.run(main())