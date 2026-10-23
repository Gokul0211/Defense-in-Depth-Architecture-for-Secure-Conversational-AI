"""
CONTROL-CHANNEL SPOOFING markers: text that impersonates the system / operator channel.

WHY (v3 code review, 2026-10-18; scratch/rca/v3/d01-d04). An assistant's instructions come from
its operator (the system prompt) and its user. A piece of text that announces itself as a
SYSTEM / ADMIN / DEVELOPER message -- or switches on a privileged "mode" -- while arriving in the
user turn or, worse, inside retrieved data, is impersonating a channel it does not come from.
That is the definition of a spoofed control message, the oldest prompt-injection family
(Greshake et al. 2023; AgentDojo's `system_message` attack; DAN / "Developer Mode").

Two shipped rules intended to catch it and did not:
  * L1 Tier 1 matched only the BARE tag `[SYSTEM]` / `[ADMIN]` -- not "[SYSTEM NOTE] ...",
    "[ADMIN OVERRIDE: ...]", "[IMPORTANT SYSTEM UPDATE: ...]", "[HIDDEN: ...]";
  * the addressee lexicon (core/addressee.py) matched "system message" but not AgentDojo's
    literal "###(system_message)", so L4's sink-context check had 0.0 recall on that family.

MEASURED BEFORE ADOPTION (d02 / d04), the rules below fire on
  benign:  0 of ~18,000 texts in 12 local benign corpora (Alpaca, NotInject, OR-Bench, WildJailbreak
           benign, WildChat / OASST multi-turn, the benign pipeline arm, AgentLeak outputs, ...) and
           5 of 170,923 real WildChat-1M user turns (user-written "[System note: ...]" steering);
           every "Developer Mode enabled" hit in WildChat is the DAN jailbreak itself;
  attack:  DIDA-Bench 62 % train / 66 % test / 100 % held_out, Phase-4 62 %, TensorTrust 0.4 %.
DISCLOSURE: the bracket family was written after reading DIDA-Bench documents (train split, the
same discipline as instruction_density's templates); its test-split gain is therefore not a clean
held-out number. The false-positive evidence above is independent of that.

Declared from the spoofing taxonomy, not fitted. `system` alone is NOT a role marker
("[System: Windows 10]" is a spec sheet): it must name a message kind ("note", "update", ...).
"""
from __future__ import annotations

import re

_LEAD = r"(?:(?:important|urgent|critical|new|official|priority)\s+)*"
# privileged roles that, opening a bracket and a directive, impersonate the control channel
_PRIV = r"(?:admin(?:istrator)?|developer|operator|root|sudo|hidden)"
# the kinds of message a control channel sends
_NOUN = (r"(?:override|update|note|notice|message|instructions?|directive|command|alert|mode|"
         r"protocol|request|order|prompt)")

PATTERNS = {
    # "[ADMIN OVERRIDE: ...]", "[HIDDEN: ...]", "[Developer note: ...]"
    "bracket_privileged": rf"\[\s*{_LEAD}{_PRIV}(?:\s+[a-z]+){{0,2}}\s*:",
    # "[SYSTEM NOTE] ...", "[IMPORTANT SYSTEM UPDATE: ...]", "[System message]"
    "bracket_system": rf"\[\s*{_LEAD}system(?:\s+[a-z]+)?\s+{_NOUN}\s*[:\]]",
    # "[Admin system instructions]"
    "bracket_named_directive": rf"\[\s*{_LEAD}{_PRIV}(?:\s+[a-z]+){{0,2}}\s+{_NOUN}\s*\]",
    # AgentDojo's system_message family: "###(system_message) ..."
    "system_message_header": r"#{2,}\s*\(\s*system[ _-]?message\s*\)",
    # "Developer Mode enabled", "DAN Mode enabled", "Emergency protocol activated", "Override active".
    # Modes with an ordinary meaning ("debug mode on", "maintenance mode", "god mode" in games,
    # "admin access granted" in logs) are deliberately NOT listed: this feeds a BLOCK-level tier.
    "privileged_mode_on": (r"\b(?:developer|dan|jailbreak|jailbroken|unrestricted|unfiltered|emergency)\s+"
                           r"(?:mode|protocol|override)\s+"
                           r"(?:is\s+|has been\s+|now\s+)*(?:enabled|activated|engaged|active|unlocked|on)\b"
                           r"|\boverride\s+(?:is\s+)?(?:active|activated|enabled|engaged)\b"),
}
COMPILED = {k: re.compile(p, re.I) for k, p in PATTERNS.items()}


def spoof_markers(text: str) -> list[str]:
    """Names of the spoofing patterns present in `text` (raw or canonicalized)."""
    if not text:
        return []
    from sentinel.core.text_canonicalize import canonicalize

    canon = canonicalize(text)
    return [k for k, rx in COMPILED.items() if rx.search(text) or rx.search(canon)]


def first_marker(text: str):
    """(name, match) of the first spoofing marker in the RAW text, or None."""
    for k, rx in COMPILED.items():
        m = rx.search(text or "")
        if m:
            return k, m
    return None
