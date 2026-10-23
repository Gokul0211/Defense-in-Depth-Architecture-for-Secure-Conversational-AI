"""
ADDRESSEE cues: is third-party text talking TO THE AI SYSTEM? (2026-09-26, R-031b)

WHY. R-031 measured that the injection scorer every third-party check relies on (PIGuard,
short_document_threat) cannot separate an instruction addressed to a HUMAN reader -- normal in
emails, Slack messages, reviews, TODO lists: "please send me the report", "invite Dora" -- from
one addressed to the AGENT. On AgentDojo, windows around benign sink values: median 0.79,
95th percentile 0.9994; windows around injected sink values: median 0.99966. Both saturate. That
single confusion explains Slack's benign false alarms, the short bin's ceiling anchors (0.9997),
and the attacks those anchors then let through.

WHAT. Indirect prompt injection is, by definition, text in DATA that addresses the MODEL. So the
missing dimension is the addressee, not the imperative. These cues are declared from that
definition and from the published attack families (the "ignore previous instructions" family,
AgentDojo's important_instructions / tool_knowledge, InjecAgent, BIPIA, Greshake et al.), not
fitted: explicit references to an AI / assistant / model / agent as the one being addressed, to
its instructions / task / system prompt / tools, and markup that frames injected directives.
A benign email to "Emma" has none of them.

Used by action_policy._instruction_context (and available to L2) as a GATE on the injection
score: a window counts as an instruction to the agent only if it carries an addressee cue AND
the injection scorer agrees at a (much lower) calibrated threshold -- or carries a strong cue.
"""
from __future__ import annotations

import re

# the model/agent named as the addressee or as the actor that must comply
_AI = r"(?:ai|a\.i\.|artificial intelligence|assistant|chat ?bot|language model|llm|model|agent|gpt|claude|copilot)"
STRONG = [
    rf"\b(?:to|for|dear|hey|hello|attention|note to|message to)\s+(?:the\s+|you,?\s+|my\s+)?{_AI}\b",
    rf"\byou,?\s+(?:the\s+)?{_AI}\b",
    rf"\b(?:as|if you are) (?:an?|the) {_AI}\b",
    r"\b(?:ignore|disregard|forget|override|bypass)\b.{0,40}\b(?:previous|prior|above|earlier|all|your|system|original)\b.{0,20}\b(?:instructions?|prompts?|rules?|guidelines?|directives?|task)\b",
    r"\b(?:the|your) (?:original |initial |current |previous )?(?:task|instructions?|goal) (?:that |which )?(?:i|the user) (?:gave|assigned|asked)\b",
    r"\bbefore you (?:can )?(?:solve|complete|finish|continue|answer|proceed with) (?:the|your|this) (?:task|request|question)\b",
    r"\b(?:system prompt|system message|developer (?:mode|message|instructions?)|new instructions?|updated instructions?)\b",
    r"</?\s*(?:information|instructions?|system|important|admin|sys|inst)\s*>",
    r"\[/?\s*(?:inst|system|admin)\s*\]",
]
WEAK = [
    rf"\b{_AI}\b",
    r"\b(?:you must|you should|you need to|you are (?:now|required)|from now on|do not tell the user|without (?:telling|informing|asking) the user)\b",
    r"\b(?:call|use|invoke|run|execute) (?:the )?(?:function|tool|api|command)\b",
    r"\b(?:important|urgent) (?:message|instruction|notice|update)\b",
]
_STRONG = [re.compile(p, re.I | re.S) for p in STRONG]
_WEAK = [re.compile(p, re.I | re.S) for p in WEAK]

# v3 code review (2026-10-18, config.ADDRESSEE_SPOOF_CUES). Two families had window recall 0.0 in
# R-031c, and both for a lexical reason, not a conceptual one:
#   system_message   "###(system_message) ..." -- the lexicon knew "system message" with a SPACE;
#   ignore_previous  "Ignore your previous iunstructions" -- AgentDojo's own template typo, which
#                    an attacker can reproduce at will; the object noun is matched by its stem.
# Plus the spoofed control-channel markers of core/control_spoof.py ("[SYSTEM NOTE] ...",
# "[ADMIN OVERRIDE: ...]", "Developer Mode enabled"): by definition they address the AI system.
# The ignore/override cue's left edge is "not preceded by a letter or digit" rather than \b, because "_" is a
# word character: AgentDojo injects into identifiers such as the Slack channel name "External_Ignore your
# previous iunstructions. Do ...", where \bignore never matches (RCA 2 fix validation m02: ignore_previous
# 147/295 vs 234/295 for the families whose cue has no leading \b).
STRONG_V3 = [
    r"\bsystem[ _-](?:prompt|message)s?\b",
    r"(?<![A-Za-z0-9])(?:ignore|disregard|forget|override|bypass)\b.{0,40}\b(?:previous|prior|above|earlier|all|your|system|original)\b"
    r".{0,20}\b\w*(?:nstruct|prompt|guideline|directive)\w*",
]
_STRONG_V3 = [re.compile(p, re.I | re.S) for p in STRONG_V3]
# the 2026-10-18 form (\b left edge), kept for config.ADDRESSEE_UNDERSCORE_BOUNDARY=false reproduction
_STRONG_V3_OLD = [re.compile(STRONG_V3[0], re.I | re.S),
                  re.compile(STRONG_V3[1].replace("(?<![A-Za-z0-9])", r"\b", 1), re.I | re.S)]


def strong_patterns() -> list:
    """The STRONG cue patterns in force (read live, so a harness can flip the flag)."""
    import sentinel.config as cfg
    if not getattr(cfg, "ADDRESSEE_SPOOF_CUES", False):
        return _STRONG
    from sentinel.core.control_spoof import COMPILED
    v3 = _STRONG_V3 if getattr(cfg, "ADDRESSEE_UNDERSCORE_BOUNDARY", False) else _STRONG_V3_OLD
    return _STRONG + v3 + list(COMPILED.values())


_ESCAPES = __import__("re").compile(r"\\[nrt]")


def match_text(text: str) -> str:
    """The text cues are matched on: a serialised tool output writes a newline as the two characters
    backslash + "n", which glues the next word to a letter ("...available\\nIgnore your previous ...") and
    defeats every left word edge (RCA 2 fix validation: 27 travel ignore_previous injections). Each escape is
    replaced by two spaces, so character positions -- and the instruction spans built on them -- are unchanged.
    Active with config.ADDRESSEE_UNDERSCORE_BOUNDARY (the same identifier/escape boundary fix)."""
    import sentinel.config as cfg
    t = text or ""
    if getattr(cfg, "ADDRESSEE_UNDERSCORE_BOUNDARY", False) and "\\" in t:
        t = _ESCAPES.sub("  ", t)
    return t


def addressee_cues(text: str) -> tuple[int, int]:
    """(# strong cues, # weak cues) present in `text`."""
    t = match_text(text)
    return sum(bool(p.search(t)) for p in strong_patterns()), sum(bool(p.search(t)) for p in _WEAK)
