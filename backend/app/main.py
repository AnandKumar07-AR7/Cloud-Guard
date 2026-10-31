"""
Entry point compatibility alias.
Allows uvicorn to launch via either `uvicorn app.main:app` or `uvicorn main:app`.
"""
import sys
from pathlib import Path

# Add backend directory to sys.path
backend_dir = str(Path(__file__).resolve().parent.parent)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from main import app
