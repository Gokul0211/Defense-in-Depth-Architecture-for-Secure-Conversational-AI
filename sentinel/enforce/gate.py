"""
Complete mediation at the tool-execution boundary (ARCHITECTURE_NEXT.md v2 §4).

L4's verdict (`should_execute`, `requires_confirmation`) is advice until something that EXECUTES tools refuses to run
a call without it. This module is that something:

  * `issue_decision(...)` -- called where the verdict is made (`/sentinel/agent/tool_call`, the proxy) -- returns a
    DECISION TOKEN: an HMAC over (version, session, principal, tool, SHA-256 of the canonical arguments, decision,
    nonce, issued-at, expiry). Nothing in it is secret; it cannot be forged without the key.
  * `approve(token, approver)` -- the user's confirmation of a `confirm` decision -- returns an APPROVAL bound to the
    same nonce and argument hash, and only the token's own principal may approve.
  * `ToolGate.execute(session, principal, tool, params, token, approval)` runs the tool only if every invariant holds:

      I1  the token verifies under the key (no key configured -> nothing executes: fail closed)
      I2  session, principal and tool match the call being executed
      I3  the canonical arguments hash to the token's hash: a call changed after authorisation is refused
      I4  not expired
      I5  single use: a nonce that executed once never executes again (replay / duplicate execution)
      I6  decision "allow", or "confirm" with a valid approval by the same principal for the same nonce
      I7  every outcome (executed or refused, and why) is appended to a hash-chained audit log that records the
          argument HASH, never the arguments

The gate does not decide anything itself; it only refuses to execute what was not decided. A deployment that calls
tools without the gate is not mediated, and `docs` must say so (the replay and the tests use it).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass, field

VERSION = 1
DEFAULT_TTL_S = 300


class GateRefused(Exception):
    def __init__(self, invariant: str, reason: str):
        super().__init__(f"{invariant}: {reason}")
        self.invariant, self.reason = invariant, reason


def _key() -> bytes | None:
    import sentinel.config as cfg
    k = getattr(cfg, "DIDA_DECISION_KEY", "") or os.getenv("DIDA_DECISION_KEY", "")
    return k.encode() if k else None


def canonical_args(params: dict) -> str:
    """Deterministic serialisation: sorted keys, no whitespace, unicode kept, floats as repr."""
    return json.dumps(params or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def args_hash(params: dict) -> str:
    return hashlib.sha256(canonical_args(params).encode("utf-8")).hexdigest()


def _b64(d: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(d, sort_keys=True, separators=(",", ":")).encode()).decode().rstrip("=")


def _unb64(s: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))


def _sign(payload: str, key: bytes) -> str:
    return hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()


def issue_decision(session_id: str, principal: str, tool: str, params: dict, decision: str,
                   ttl_s: int = DEFAULT_TTL_S, reasons: list | None = None, key: bytes | None = None) -> str | None:
    """A signed decision for exactly this call, or None when no key is configured (the caller then has nothing a
    gate would accept -- fail closed). `decision` is "allow" or "confirm"; a block gets no token."""
    if decision not in ("allow", "confirm"):
        return None
    key = key or _key()
    if not key:
        return None
    now = int(time.time())
    body = {"v": VERSION, "sid": session_id, "pr": principal, "tool": tool, "ah": args_hash(params),
            "dec": decision, "nonce": secrets.token_hex(12), "iat": now, "exp": now + int(ttl_s),
            "rh": hashlib.sha256(json.dumps(reasons or [], default=str).encode()).hexdigest()[:16]}
    p = _b64(body)
    return f"{p}.{_sign(p, key)}"


def read_token(token: str, key: bytes | None = None) -> dict:
    key = key or _key()
    if not key:
        raise GateRefused("I1", "no decision key configured")
    try:
        p, sig = token.rsplit(".", 1)
    except (AttributeError, ValueError):
        raise GateRefused("I1", "malformed token") from None
    if not hmac.compare_digest(_sign(p, key), sig):
        raise GateRefused("I1", "bad signature")
    try:
        body = _unb64(p)
    except Exception:                                                 # noqa: BLE001
        raise GateRefused("I1", "malformed token body") from None
    if body.get("v") != VERSION:
        raise GateRefused("I1", "unknown token version")
    return body


def approve(token: str, approver: str, key: bytes | None = None) -> str:
    """The user's confirmation of a `confirm` decision, bound to its nonce and argument hash."""
    key = key or _key()
    body = read_token(token, key)
    if body["dec"] != "confirm":
        raise GateRefused("I6", "only a confirm decision can be approved")
    if approver != body["pr"]:
        raise GateRefused("I6", "approver is not the principal the decision was issued to")
    if body["exp"] < time.time():
        raise GateRefused("I4", "decision expired before approval")
    a = {"v": VERSION, "kind": "approval", "nonce": body["nonce"], "ah": body["ah"], "pr": approver,
         "at": int(time.time())}
    p = _b64(a)
    return f"{p}.{_sign(p, key)}"


@dataclass
class AuditLog:
    records: list = field(default_factory=list)
    _head: str = "0" * 64

    def append(self, rec: dict) -> dict:
        rec = {**rec, "ts": time.time(), "prev": self._head}
        h = hashlib.sha256(json.dumps(rec, sort_keys=True, default=str).encode()).hexdigest()
        rec["hash"] = h
        self._head = h
        self.records.append(rec)
        return rec

    def verify(self) -> bool:
        prev = "0" * 64
        for r in self.records:
            body = {k: v for k, v in r.items() if k != "hash"}
            if body["prev"] != prev or hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest() != r["hash"]:
                return False
            prev = r["hash"]
        return True


class ToolGate:
    """Executes a tool only under a valid decision (I1-I7). `executors`: tool name -> callable(**params)."""

    def __init__(self, executors: dict | None = None, key: bytes | None = None, audit: AuditLog | None = None):
        self.executors = executors or {}
        self._key = key
        self.audit = audit or AuditLog()
        self._used: set[str] = set()
        self._lock = threading.Lock()

    def check(self, session_id: str, principal: str, tool: str, params: dict, token: str | None,
              approval: str | None = None) -> dict:
        """Validate without executing; returns the token body. Raises GateRefused."""
        key = self._key or _key()
        if not token:
            raise GateRefused("I1", "no decision token (call was not authorised, or was blocked)")
        body = read_token(token, key)
        if body["sid"] != session_id:
            raise GateRefused("I2", "token issued for another session")
        if body["pr"] != principal:
            raise GateRefused("I2", "token issued for another principal")
        if body["tool"] != tool:
            raise GateRefused("I2", "token issued for another tool")
        if body["ah"] != args_hash(params):
            raise GateRefused("I3", "arguments changed after authorisation")
        if body["exp"] < time.time():
            raise GateRefused("I4", "decision expired")
        with self._lock:
            if body["nonce"] in self._used:
                raise GateRefused("I5", "decision already used")
        if body["dec"] == "confirm":
            if not approval:
                raise GateRefused("I6", "decision requires the user's confirmation")
            a = read_token(approval, key)
            if a.get("kind") != "approval" or a.get("nonce") != body["nonce"] or a.get("ah") != body["ah"]:
                raise GateRefused("I6", "approval does not match this decision")
            if a.get("pr") != principal:
                raise GateRefused("I6", "approval by another principal")
        elif body["dec"] != "allow":
            raise GateRefused("I6", f"decision {body['dec']!r} does not permit execution")
        return body

    def execute(self, session_id: str, principal: str, tool: str, params: dict, token: str | None,
                approval: str | None = None, executor=None):
        try:
            body = self.check(session_id, principal, tool, params, token, approval)
        except GateRefused as e:
            self.audit.append({"sid": session_id, "pr": principal, "tool": tool, "ah": args_hash(params),
                               "outcome": "refused", "invariant": e.invariant, "reason": e.reason})
            raise
        with self._lock:                      # claim the nonce BEFORE running: a concurrent duplicate is refused
            if body["nonce"] in self._used:
                self.audit.append({"sid": session_id, "pr": principal, "tool": tool, "ah": body["ah"],
                                   "outcome": "refused", "invariant": "I5", "reason": "decision already used"})
                raise GateRefused("I5", "decision already used")
            self._used.add(body["nonce"])
        fn = executor or self.executors.get(tool)
        if fn is None:
            self.audit.append({"sid": session_id, "pr": principal, "tool": tool, "ah": body["ah"],
                               "outcome": "refused", "invariant": "I0", "reason": "no executor registered"})
            raise GateRefused("I0", "no executor registered for this tool")
        try:
            result = fn(**(params or {}))
            outcome = "executed"
            return result
        except Exception as e:                                        # noqa: BLE001
            outcome = f"executed_with_error:{type(e).__name__}"
            raise
        finally:
            self.audit.append({"sid": session_id, "pr": principal, "tool": tool, "ah": body["ah"],
                               "decision": body["dec"], "nonce": body["nonce"], "outcome": outcome})
