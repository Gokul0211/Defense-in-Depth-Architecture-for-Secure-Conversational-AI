"""
Sink classes: what each ARGUMENT of a side-effecting tool controls (ARCHITECTURE_NEXT.md v2 §2a).

The capability of a tool (action_policy.capability) says what the call can do; the sink class of an
argument says what that argument decides -- where money goes, who receives a message, who gains access,
which object is destroyed. Authorization is decided per argument: the same IBAN is harmless in a
transaction subject and decisive in `recipient`.

Declared from tool semantics (AgentDojo v1.2 suites + generic names), not fitted to any result. Tools the
table does not list fall to parameter-name heuristics; an argument nothing matches is INTERNAL.
"""
from __future__ import annotations

import re

MONEY_DESTINATION = "MONEY_DESTINATION"
AMOUNT = "AMOUNT"
EXTERNAL_RECIPIENT = "EXTERNAL_RECIPIENT"
ACCESS = "ACCESS"
CREDENTIAL = "CREDENTIAL"
PUBLICATION = "PUBLICATION"
EXECUTION = "EXECUTION"
DESTRUCTIVE_TARGET = "DESTRUCTIVE_TARGET"
INTERNAL = "INTERNAL"
# What a booking / order / purchase commits the user to (hotel, restaurant, car company, product, flight). It decides
# where the user's money or obligation goes, like a payee -- it was INTERNAL until 2026-10-21 (scratch/rca/v5: an
# injected reserve_hotel target from a user-named review passed both the matrix and the contract binding).
COMMITMENT_TARGET = "COMMITMENT_TARGET"
CONTENT = "CONTENT"

SINK_CLASSES = (COMMITMENT_TARGET, MONEY_DESTINATION, AMOUNT, EXTERNAL_RECIPIENT, ACCESS, CREDENTIAL, PUBLICATION,
                EXECUTION, DESTRUCTIVE_TARGET, INTERNAL, CONTENT)

_MONEY = {"recipient": MONEY_DESTINATION, "amount": AMOUNT, "subject": CONTENT, "date": INTERNAL,
          "recurring": INTERNAL, "id": INTERNAL}
_MAIL = {"recipients": EXTERNAL_RECIPIENT, "cc": EXTERNAL_RECIPIENT, "bcc": EXTERNAL_RECIPIENT,
         "subject": CONTENT, "body": CONTENT, "attachments": INTERNAL}
_EVENT = {"participants": EXTERNAL_RECIPIENT, "title": CONTENT, "description": CONTENT}

EXPLICIT_SINKS: dict[str, dict[str, str]] = {
    "send_money": _MONEY, "schedule_transaction": _MONEY, "update_scheduled_transaction": _MONEY,
    "update_password": {"password": CREDENTIAL},
    "update_user_info": {},
    "send_email": _MAIL,
    "create_calendar_event": _EVENT,
    "add_calendar_event_participants": {"participants": EXTERNAL_RECIPIENT},
    "append_to_file": {"content": CONTENT}, "create_file": {"content": CONTENT},
    "share_file": {"email": EXTERNAL_RECIPIENT, "permission": ACCESS},
    "delete_file": {"file_id": DESTRUCTIVE_TARGET}, "delete_email": {"email_id": DESTRUCTIVE_TARGET},
    "cancel_calendar_event": {"event_id": DESTRUCTIVE_TARGET},
    "remove_user_from_slack": {"user": DESTRUCTIVE_TARGET},
    "send_direct_message": {"recipient": EXTERNAL_RECIPIENT, "body": CONTENT},
    "send_channel_message": {"channel": EXTERNAL_RECIPIENT, "body": CONTENT},
    "post_webpage": {"url": PUBLICATION, "content": CONTENT},
    "invite_user_to_slack": {"user": ACCESS, "user_email": ACCESS},
    "add_user_to_channel": {"user": ACCESS, "channel": ACCESS},
    "reserve_hotel": {"hotel": COMMITMENT_TARGET}, "reserve_restaurant": {"restaurant": COMMITMENT_TARGET},
    "reserve_car_rental": {"company": COMMITMENT_TARGET},
}

# Generic parameter names, tried in order when a tool is not in EXPLICIT_SINKS.
_NAME_RULES = [
    (r"(password|passcode|secret|token|api_?key|credential|otp|pin)$", CREDENTIAL),
    (r"(iban|account(_number)?|payee|beneficiary|routing)$", MONEY_DESTINATION),
    (r"(command|cmd|code|script|sql|shell|expression)$", EXECUTION),
    (r"(role|permission|permissions|scope|access(_level)?)$", ACCESS),
    (r"(url|endpoint|webhook|link|uri)$", PUBLICATION),
    (r"(recipients?|to|cc|bcc|emails?|participants|attendees|invitees|phone(_number)?|channel|user(name)?|user_email)$",
     EXTERNAL_RECIPIENT),
    (r"(body|content|message|text|subject|title|description|note|notes|comment|summary)$", CONTENT),
]


def sink_class(tool_name: str, param: str, capability: str) -> str:
    """Sink class of one argument. `capability` is action_policy.capability(tool_name)."""
    tool = (tool_name or "").strip().lower()
    p = (param or "").strip().lower()
    table = EXPLICIT_SINKS.get(tool)
    if table is not None:
        return table.get(p, INTERNAL)
    if capability == "TRANSFER":
        if re.search(r"(recipient|to|iban|account|payee|beneficiary)$", p):
            return MONEY_DESTINATION
        if re.search(r"(amount|sum|value|price|total)$", p):
            return AMOUNT
    if re.search(r"(^|_)(reserve|book|order|purchase|buy|subscribe|enroll|register)(_|$)", tool) and re.search(
            r"(hotel|restaurant|company|vendor|merchant|product|item|sku|flight|venue|provider|seller|listing|plan|"
            r"service|event|course|property|room|offer)(_?(id|name))?$", p):
        return COMMITMENT_TARGET
    if capability == "DESTROY" and re.search(r"(^|_)(id|ids|target|name|path|user|file)$", p):
        return DESTRUCTIVE_TARGET
    if capability == "EXECUTE" and not re.search(r"(timeout|limit|format)$", p):
        return EXECUTION
    for pat, cls in _NAME_RULES:
        if re.search(pat, p):
            return cls
    return INTERNAL
