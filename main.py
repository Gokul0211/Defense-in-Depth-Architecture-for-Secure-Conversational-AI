"""
SENTINEL — Entry Point

Starts the unified FastAPI server on port 8080.
Serves the proxy, WebSocket, REST API, and dashboard.
"""

import uvicorn
from sentinel.config import HOST, PORT

if __name__ == "__main__":
    uvicorn.run(
        "sentinel.app:app",
        host=HOST,
        port=PORT,
        reload=False,
        log_level="info",
    )
