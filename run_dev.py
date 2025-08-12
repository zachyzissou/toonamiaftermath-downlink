#!/usr/bin/env python3
"""Development runner for Toonami Aftermath: Downlink"""

import os
import sys
from pathlib import Path

# Set up environment
base_dir = Path(__file__).parent.absolute()
os.environ["DATA_DIR"] = str(base_dir / "data")
os.environ["WEB_DIR"] = str(base_dir / "web")
os.environ["PORT"] = "7005"

# Ensure data directory exists
(base_dir / "data").mkdir(exist_ok=True)

print("Starting Toonami Aftermath: Downlink")
print(f"Data directory: {os.environ['DATA_DIR']}")
print(f"Web directory: {os.environ['WEB_DIR']}")
print(f"Port: {os.environ['PORT']}")

# Import and run
sys.path.insert(0, str(base_dir))

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.server:create_app", host="0.0.0.0", port=7005, factory=True, reload=False
    )
