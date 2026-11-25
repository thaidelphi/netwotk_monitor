"""Windowless launcher (.pyw) — Double-click on Windows to launch GUI without a console window."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ui import launch_app

if __name__ == "__main__":
    launch_app()
