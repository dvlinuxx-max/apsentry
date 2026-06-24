#!/usr/bin/env python3
"""Run apsentry without installing: python apsentry.py [args]"""
from apsentry.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
