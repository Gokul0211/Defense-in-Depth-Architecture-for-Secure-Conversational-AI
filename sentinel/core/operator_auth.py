"""
Operator authentication for knowledge-base administration (L2 review C3, 2026-10-28).

The RAG endpoints let ANY caller tamper with a stored chunk (/sentinel/rag/tamper), remove any document from retrieval
(/sentinel/rag/quarantine), and read the full text of every stored chunk including quarantined ones
(/sentinel/rag/chunks). These now distinguish an OPERATOR:

  * header `X-DIDA-Operator-Key` equal to config.DIDA_OPERATOR_KEY (constant-time compare), or
  * config.DIDA_OPERATOR_OPEN=true -- local development only, the same escape hatch as DIDA_APPROVE_OPEN.

Unset key and not open -> nobody is an operator (fail closed), exactly the posture /sentinel/agent/approve took (v7 R8).
The tamper endpoint is a DEMONSTRATION of the integrity check and additionally needs config.DIDA_DEMO_ENDPOINTS=true.
"""
from __future__ import annotations

import hmac

from fastapi import HTTPException, Request

HEADER = "X-DIDA-Operator-Key"


def is_operator(request: Request) -> bool:
    import sentinel.config as cfg
    if getattr(cfg, "DIDA_OPERATOR_OPEN", False):
        return True
    key = getattr(cfg, "DIDA_OPERATOR_KEY", "") or ""
    got = request.headers.get(HEADER, "")
    return bool(key) and bool(got) and hmac.compare_digest(got.encode(), key.encode())


def require_operator(request: Request) -> None:
    if not is_operator(request):
        raise HTTPException(status_code=403, detail=(
            f"Operator only: send {HEADER} (config DIDA_OPERATOR_KEY), or set DIDA_OPERATOR_OPEN=true for local "
            "development."))


def require_demo_endpoints(request: Request) -> None:
    import sentinel.config as cfg
    if not getattr(cfg, "DIDA_DEMO_ENDPOINTS", False):
        raise HTTPException(status_code=403, detail="Demonstration endpoint disabled (set DIDA_DEMO_ENDPOINTS=true).")
    require_operator(request)
