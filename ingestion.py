"""
ingestion.py - Wrapper in Ghost-Print root importing from code/ingestion.py
"""
import sys
from pathlib import Path

cur = Path(__file__).resolve().parent
code_dir = cur / "code"
if code_dir.is_dir() and str(code_dir) not in sys.path:
    sys.path.insert(0, str(code_dir))

from ingestion import *

if __name__ == "__main__":
    import subprocess
    target = code_dir / "ingestion.py"
    subprocess.run([sys.executable, str(target)])

