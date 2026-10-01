#!/usr/bin/env python3
"""Compatibility entry point retained for the original submission layout."""

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.aegisguard.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
