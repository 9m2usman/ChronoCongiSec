"""Entry point for Demo 2 in demo/blocked_action directory."""

import sys
from pathlib import Path

# Add project root to path
root_dir = Path(__file__).resolve().parent.parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from demo.run_demo2 import main

if __name__ == "__main__":
    main()
