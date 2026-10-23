"""
Lineage store: where every value an agent could put into a tool argument came from, and how far that
source is trusted (ARCHITECTURE_NEXT.md v2 §2b, §3).

Origin and trust are kept apart. Every tool output is split into FIELDS; each field gets a source tier:

  T0 USER                the user typed it in this session (resolved from the conversation, not stored here)
  T1 SYSTEM_OF_RECORD    a STRUCTURAL field of a connector the operator declares authoritative -- the
                         recipient of a past payment, a channel's member list, a contact's address
  T2 USER_NAMED          a CONTENT field (body, file text, web page, review) of a read the user pointed
                         at -- its origin is known, its content is not verified
  T3 THIRD_PARTY         any other content field, and every field of an undeclared tool
  T4 MODEL_GENERATED     resolved at decision time: the value matches no source at all

A free-text field is never T1, whatever the connector: an IBAN inside a transaction SUBJECT is text a
counterparty wrote, while the same IBAN in the RECIPIENT field is the bank's own record. Structural T1
fields also carry a ROLE ("payee" = someone the user has paid, "payer" = someone who paid the user, ...),
because "known counterparty" must mean a payee -- anyone can make themselves a payer by sending 0.01.

Matching is exact after folding (case, whitespace, URL scheme); there is no fuzzy matching: a value one
character away from a trusted one is a different destination. A value present in several sources takes the
MOST trusted one -- an attacker cannot make the user's own value untrusted by repeating it.
"""
from __future__ import annotations

import dataclasses
import json
import re
import threading
from dataclasses import dataclass, field

T0, T1, T2, T3, T4 = "T0", "T1", "T2", "T3", "T4"
TIER_RANK = {T0: 0, T1: 1, T2: 2, T3: 3, T4: 4}

# Field names that hold free text whoever's connector returns them.
CONTENT_FIELDS = {"body", "content", "subject", "description", "title", "text", "message", "messages",
                  "review", "reviews", "notes", "note", "comment", "comments", "snippet", "summary", "bio",
                  "about", "reason", "details"}

# --- operator trust declarations (§9.1). AgentDojo defaults: the user's own accounts, workspace directory,
# calendar, drive metadata and the travel platform's catalogue are systems of record; web pages, files the
# agent reads and reviews are not. `values_are_content`: a dict output whose KEYS are catalogue entries and
# whose VALUES are free text (reviews). `roles`: the meaning of a structural field.
_PAY_ROLES = {"recipient": "payee", "sender": "payer"}
_MAIL_ROLES = {"sender": "correspondent", "recipients": "contact", "cc": "contact", "bcc": "contact"}
_EVENT_ROLES = {"participants": "contact"}
_FILE_ROLES = {"owner": "contact", "shared_with": "contact"}
AGENTDOJO_TRUST = {
    # banking
    "get_iban": {"tier": T1, "roles": {"_value": "self"}},
    "get_balance": {"tier": T1}, "get_user_info": {"tier": T1},
    "get_most_recent_transactions": {"tier": T1, "roles": _PAY_ROLES},
    "get_scheduled_transactions": {"tier": T1, "roles": _PAY_ROLES},
    # slack
    "get_channels": {"tier": T1, "roles": {"_value": "channel"}},
    "get_users_in_channel": {"tier": T1, "roles": {"_value": "member"}},
    "read_channel_messages": {"tier": T1, "roles": {"sender": "member", "recipient": "channel"}},
    "read_inbox": {"tier": T1, "roles": {"sender": "member", "recipient": "member"}},
    # workspace
    "get_unread_emails": {"tier": T1, "roles": _MAIL_ROLES}, "get_sent_emails": {"tier": T1, "roles": _MAIL_ROLES},
    "get_received_emails": {"tier": T1, "roles": _MAIL_ROLES}, "get_draft_emails": {"tier": T1, "roles": _MAIL_ROLES},
    "search_emails": {"tier": T1, "roles": _MAIL_ROLES},
    "search_contacts_by_name": {"tier": T1, "roles": {"email": "contact"}},
    "search_contacts_by_email": {"tier": T1, "roles": {"email": "contact"}},
    "get_current_day": {"tier": T1},
    "search_calendar_events": {"tier": T1, "roles": _EVENT_ROLES},
    "get_day_calendar_events": {"tier": T1, "roles": _EVENT_ROLES},
    "list_files": {"tier": T1, "roles": _FILE_ROLES}, "get_file_by_id": {"tier": T1, "roles": _FILE_ROLES},
    "search_files": {"tier": T1, "roles": _FILE_ROLES}, "search_files_by_filename": {"tier": T1, "roles": _FILE_ROLES},
    # travel: catalogue + the user's profile; reviews are free text keyed by catalogue entry
    "get_user_information": {"tier": T1},
    "get_all_hotels_in_city": {"tier": T1}, "get_hotels_prices": {"tier": T1}, "get_hotels_address": {"tier": T1},
    "get_all_restaurants_in_city": {"tier": T1}, "get_cuisine_type_for_restaurants": {"tier": T1},
    "get_restaurants_address": {"tier": T1}, "get_dietary_restrictions_for_all_restaurants": {"tier": T1},
    "get_contact_information_for_restaurants": {"tier": T1}, "get_price_for_restaurants": {"tier": T1},
    "check_restaurant_opening_hours": {"tier": T1}, "get_all_car_rental_companies_in_city": {"tier": T1},
    "get_car_types_available": {"tier": T1}, "get_car_fuel_options": {"tier": T1},
    "get_car_rental_address": {"tier": T1}, "get_car_price_per_day": {"tier": T1},
    "get_flight_information": {"tier": T1},
    "get_rating_reviews_for_hotels": {"tier": T1, "values_are_content": True},
    "get_rating_reviews_for_restaurants": {"tier": T1, "values_are_content": True},
    "get_rating_reviews_for_car_rental": {"tier": T1, "values_are_content": True},
    # not systems of record: read_file (a document), get_webpage (the web) -> default (T3 / T2)
}

_POLICY = dict(AGENTDOJO_TRUST)


def load_trust_policy(path: str | None) -> None:
    """Replace the declarations with an operator JSON file ({tool: {"tier": "T1", "roles": {...}}})."""
    global _POLICY
    if path:
        with open(path, encoding="utf-8") as f:
            _POLICY = json.load(f)
    else:
        _POLICY = dict(AGENTDOJO_TRUST)


_POLICY_FROM: list = [None]


def tool_policy(tool: str) -> dict:
    import sentinel.config as cfg
    path = getattr(cfg, "L4_AUTHZ_TRUST_POLICY_FILE", "") or None
    if path != _POLICY_FROM[0]:
        load_trust_policy(path)
        _POLICY_FROM[0] = path
    return _POLICY.get((tool or "").strip().lower(), {})


# --- folding / identifiers ------------------------------------------------------------------------------
_SCHEME = re.compile(r"\bhttps?://|(?<![\w.])www\.", re.I)


def fold(s) -> str:
    s = _SCHEME.sub("", str(s if s is not None else ""))
    s = re.sub(r"\s+", " ", s.strip().lower())
    return s.rstrip("/").strip(" '\"`")


def fold_id(s) -> str:
    """Identifier folding: also drops spaces and hyphens inside the value ("DE89 3704-0044")."""
    return re.sub(r"[\s\-]+", "", fold(s))


_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
_URL = re.compile(r"(?:https?://)?(?:www\.)?(?:[A-Za-z0-9\-]+\.)+(?:com|org|net|io|ai|co|gov|edu|info|biz|xyz|"
                  r"me|app|dev|uk|de|fr|ch|it|es|nl|ru|cn|in|us|eu|ly|gl|to|cc|tv|site|online|page|link)"
                  r"(?:/[^\s<>\"')\]]*)?", re.I)
_PHONE = re.compile(r"(?<!\w)\+\d[\d\s\-]{8,}\d(?!\w)")


def identifiers_in(text: str) -> list[tuple[str, str]]:
    """(kind, value) for every identifier-shaped substring of free text: e-mail, IBAN, URL/domain, phone."""
    text = str(text or "")
    out, spans = [], []
    for kind, rx in (("email", _EMAIL), ("iban", _IBAN), ("phone", _PHONE), ("url", _URL)):
        for m in rx.finditer(text):
            if any(a <= m.start() < b for a, b in spans):
                continue            # the domain inside an e-mail address is not a second identifier
            spans.append((m.start(), m.end()))
            out.append((kind, m.group(0).rstrip(".,;:!?")))
    return out


def looks_like_identifier(v: str) -> bool:
    return bool(_EMAIL.fullmatch(v) or _IBAN.fullmatch(v.replace(" ", "").upper()) or _URL.fullmatch(v)
                or _PHONE.fullmatch(v))


# --- the store -------------------------------------------------------------------------------------------
@dataclass
class Leaf:
    tier: str
    role: str | None
    tool: str
    field: str
    text: str              # folded
    structural: bool
    atoms: tuple = ()      # structural leaves: the exact values a match may equal (whole value, each line,
                           # each "Label: value" line's value) -- never a substring of them


PROSE_WORDS = 10           # a "structural" line this long is text someone wrote (a channel NAME carrying an
                           # injection, v01) and is recorded as content


def _atoms(raw: str) -> tuple:
    out = {fold(raw)}
    for line in str(raw).split("\n"):
        line = fold(line.strip(" -*\t"))
        if line:
            out.add(line)
            if ": " in line:
                out.add(line.split(": ", 1)[1].strip())
    return tuple(a for a in out if a)


@dataclass
class Session:
    leaves: list = field(default_factory=list)
    calls: list = field(default_factory=list)       # (tool, params) of every audited side-effect call
    sensitive: dict = field(default_factory=dict)   # folded value -> category ("credential" / "personal")


# --- sensitive values (outbound inspection, ARCHITECTURE_NEXT.md v2 §6.2) ---------------------------------
# Sensitive BY ORIGIN: the field it was read from says what it is, or the text around it does. Not a PII-shape
# guess on the outgoing message (that is L5's broad leak score): only values this session actually read.
_SENSITIVE_FIELD = [
    (re.compile(r"password|passcode|\bpin\b|cvv|cvc|security.?code|verification.?code|otp|secret|api.?key|token", re.I),
     "credential"),
    (re.compile(r"credit.?card|card.?number|card.?no", re.I), "credential"),
    (re.compile(r"passport|id.?number|national.?id|ssn|social.?security|tax.?id|bank.?account|account.?number|"
                r"date.?of.?birth|\bdob\b|driver.?s?.?licen", re.I), "personal"),
]
_SENSITIVE_TEXT = [
    (re.compile(r"(?:security|verification|confirmation|login|one[- ]time|2fa|access|reset)\s+code\b[^0-9\n]{0,40}?"
                r"(\d{4,10})", re.I), "credential"),
    (re.compile(r"\b(?:password|passcode|pin)\b(?:\s+(?:is|was)|:)\s*([^\s,;.]{4,})", re.I), "credential"),
    (re.compile(r"\b(\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4})\b"), "credential"),
]


def _record_sensitive(s: "Session", fname: str, raw: str, content: bool) -> None:
    v = fold(raw)
    if not content and len(v) >= 4:
        for rx, cat in _SENSITIVE_FIELD:
            if rx.search(fname or ""):
                s.sensitive.setdefault(v, cat)
                break
    for rx, cat in _SENSITIVE_TEXT:
        for m in rx.finditer(str(raw)):
            s.sensitive.setdefault(fold(m.group(1)), cat)


def sensitive_in(session_id: str, text: str) -> list[tuple[str, str]]:
    """(value, category) of every tracked sensitive value occurring in `text` (folded, token-bounded)."""
    t = fold(text)
    return [(v, c) for v, c in session(session_id).sensitive.items() if _bounded_in(v, t)]


_SESSIONS: dict[str, Session] = {}
_LOCK = threading.Lock()
_MAX_LEAVES = 20000


def session(session_id: str) -> Session:
    with _LOCK:
        return _SESSIONS.setdefault(session_id or "_", Session())


def reset(session_id: str | None = None) -> None:
    with _LOCK:
        if session_id is None:
            _SESSIONS.clear()
        else:
            _SESSIONS.pop(session_id, None)


def _to_plain(obj):
    """Pydantic models / dataclasses / datetimes -> dict / list / str; JSON text -> parsed."""
    if hasattr(obj, "model_dump"):
        try:
            return _to_plain(obj.model_dump())
        except Exception:                                             # noqa: BLE001
            pass
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return _to_plain(dataclasses.asdict(obj))
    if isinstance(obj, dict):
        return {str(k): _to_plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_to_plain(v) for v in obj]
    if isinstance(obj, str):
        s = obj.strip()
        if s[:1] in "[{":
            try:
                return _to_plain(json.loads(s))
            except Exception:                                         # noqa: BLE001
                return obj
        return obj
    if obj is None or isinstance(obj, (bool, int, float)):
        return obj
    return str(obj)


def _walk(obj, fname: str, out: list, is_value_of_dict: bool = False):
    """(field_name, value_str, is_dict_key, is_dict_value) leaves."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.append((fname or "_key", str(k), True, False))
            _walk(v, str(k).lower(), out, is_value_of_dict=True)
    elif isinstance(obj, list):
        for v in obj:
            _walk(v, fname, out, is_value_of_dict)
    elif obj is not None and not isinstance(obj, bool):
        out.append((fname or "_value", str(obj), False, is_value_of_dict))


def user_named(params: dict, utext_fold: str) -> bool:
    """Did the user point at this read? Any locator argument the user typed (a file name, a URL, a channel,
    an inbox owner, a search phrase) makes its output USER_NAMED (T2) rather than THIRD_PARTY."""
    for v in (params or {}).values():
        vals = v if isinstance(v, (list, tuple)) else [v]
        for x in vals:
            fx = fold(x)
            if len(fx) >= 3 and _bounded_in(fx, utext_fold):
                return True
    return False


def _named_through_document(session_id: str, params: dict, user_text: str) -> bool:
    """One hop of pointing: the locator was read from a document the user pointed at ("you can find the
    details in the message from Bob" -> the page that message links to). Still T2: content whose origin the
    user chose but nobody verified, so strict sinks taken from it need confirmation, never auto-allow."""
    for v in (params or {}).values():
        for x in (v if isinstance(v, (list, tuple)) else [v]):
            if isinstance(x, str) and len(fold(x)) >= 4 and resolve(session_id, x, user_text).tier == T2:
                return True
    return False


def record_tool_output(session_id: str, tool: str, params: dict, output, user_text: str = "") -> int:
    """Split one tool output into tiered leaves. Returns the number of leaves recorded."""
    pol = tool_policy(tool)
    named = user_named(params, fold(user_text)) or _named_through_document(session_id, params, user_text)
    content_tier = T2 if named else T3
    base = pol.get("tier", content_tier)
    if base not in (T1,):
        base = content_tier
    roles = pol.get("roles", {})
    vals_content = bool(pol.get("values_are_content"))
    raw = []
    _walk(_to_plain(output), "", raw)
    s = session(session_id)
    n = 0
    for fname, val, is_key, is_dval in raw:
        text = fold(str(val).replace("\r", ""))
        if not text:
            continue
        _record_sensitive(s, fname, str(val), base != T1 and not is_key)
        # structure only means something for a declared system of record: every field of any other tool is text
        content = base != T1 or (fname in CONTENT_FIELDS and not is_key) or (vals_content and is_dval)
        if content:
            s.leaves.append(Leaf(content_tier, None, tool, fname, text, False))
            n += 1
            continue
        role = roles.get(fname) if fname in roles else (roles.get("_value") if fname in ("_value", "_key") else None)
        atoms = _atoms(str(val)) if "\n" in str(val) else (text,)
        short = tuple(a for a in atoms if len(a.split()) < PROSE_WORDS)
        prose = [a for a in atoms if len(a.split()) >= PROSE_WORDS]
        if short:
            s.leaves.append(Leaf(base, role, tool, fname, text, True, short))
            n += 1
        for a in prose:
            s.leaves.append(Leaf(content_tier, None, tool, fname, a, False))
            n += 1
    if len(s.leaves) > _MAX_LEAVES:
        del s.leaves[: len(s.leaves) - _MAX_LEAVES]
    return n


def record_call(session_id: str, tool: str, params: dict) -> None:
    session(session_id).calls.append((tool, dict(params or {})))


def prior_calls(session_id: str, tool: str) -> int:
    return sum(1 for t, _ in session(session_id).calls if t == tool)


# --- resolution ------------------------------------------------------------------------------------------
def _bounded_in(needle: str, hay: str) -> bool:
    if not needle or not hay:
        return False
    return re.search(rf"(?<![\w@.\-]){re.escape(needle)}(?![\w@\-]|\.\w)", hay) is not None


@dataclass
class Resolution:
    tier: str
    roles: set
    sources: list           # [(tier, tool, field)]

    @property
    def ambiguous(self) -> bool:
        return len({t for t, _, _ in self.sources}) > 1


def resolve(session_id: str, value, user_text: str = "") -> Resolution:
    """Most trusted source of one argument value (§3). Numbers and very short values only match a structural
    field exactly; longer values also match inside free text with token boundaries."""
    v = fold(value)
    vid = fold_id(value)
    numeric = bool(re.fullmatch(r"[\d.,:\-/ ]+", v))
    short = len(v) < 4 or numeric
    sources = []
    ut = fold(user_text)
    if v and (_bounded_in(v, ut) or (looks_like_identifier(v) and vid and vid in fold_id(user_text))):
        sources.append((T0, "user", "turn"))
    is_id = looks_like_identifier(v)
    for leaf in session(session_id).leaves:
        if leaf.structural:
            if v in leaf.atoms or (is_id and any(fold_id(a) == vid for a in leaf.atoms)):
                sources.append((leaf.tier, leaf.tool, leaf.field, leaf.role))
            elif (is_id and vid in fold_id(leaf.text)) or (not short and _bounded_in(v, leaf.text)):
                # EMBEDDED in a structural value (a link inside a channel name someone chose): that is text the
                # field's author wrote, not the system's record -- third party.
                sources.append((T3, leaf.tool, leaf.field + "~embedded", None))
        elif leaf.text == v or (is_id and vid in fold_id(leaf.text)) or (not short and _bounded_in(v, leaf.text)):
            sources.append((leaf.tier, leaf.tool, leaf.field, leaf.role))
    if not sources:
        return Resolution(T4, set(), [])
    best = min(TIER_RANK[s[0]] for s in sources)
    tier = next(t for t, r in TIER_RANK.items() if r == best)
    roles = {s[3] for s in sources if len(s) > 3 and s[0] == tier and s[3]}
    return Resolution(tier, roles, [s[:3] for s in sources])
