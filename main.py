"""
SENTINEL — Entry Point

Starts the unified FastAPI server on port 8080.
Serves the proxy, WebSocket, REST API, and dashboard.
"""

import os

import uvicorn
from sentinel.config import HOST, PORT

if __name__ == "__main__":
    # The real server loads its models in the background at startup (sentinel/app.py
    # _warm_models). Opt-in here, so tests and imports never start that thread.
    os.environ.setdefault("DIDA_WARMUP", "1")
    uvicorn.run(
        "sentinel.app:app",
        host=HOST,
        port=PORT,
        reload=False,
        log_level="info",
    )
