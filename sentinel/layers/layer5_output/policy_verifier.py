import yaml
import os

POLICY_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "sentinel_policy.yaml")

def load_policy():
    try:
        with open(POLICY_PATH, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        return {}

def verify_policy(response: str) -> list[str]:
    """
    Verify response against output policy.
    Returns a list of policy violations.
    """
    policy = load_policy()
    if not policy or "output_policy" not in policy:
        return []
        
    violations = []
    out_pol = policy["output_policy"]
    resp_lower = response.lower()

    import sentinel.config as cfg
    if getattr(cfg, "L5_POLICY_PHRASE_MATCH", False):
        return _verify_policy_phrases(out_pol, resp_lower)

    # Check forbidden topics
    if "forbidden_topics" in out_pol:
        for topic in out_pol["forbidden_topics"]:
            # Split topic like "guarantee_returns" into keyword stems
            keywords = [kw for kw in topic.split("_") if len(kw) > 3]
            if not keywords:
                continue
            # Require ALL of the topic's keyword stems to be present before
            # flagging it. This was previously an ANY match, which meant a
            # single unrelated word (e.g. "return" as in "return the item")
            # was enough to trigger "guarantee_returns" with no relation to
            # "guarantee" at all — a guaranteed high false-positive rate on
            # any topic with more than one keyword stem. Requiring all stems
            # to co-occur is still just bag-of-words (not phrase-adjacency),
            # but it fixes the single-keyword false-positive failure mode.
            if all(any(kw in word for word in resp_lower.split()) for kw in keywords):
                violations.append(f"Forbidden topic detected: {topic}")
                
    # Check required disclaimers
    if "required_disclaimers" in out_pol:
        for req in out_pol["required_disclaimers"]:
            cond = req["condition"].lower()
            if all(w in resp_lower for w in cond.split()):
                if req["disclaimer"].lower() not in resp_lower:
                    violations.append(f"Missing required disclaimer for condition: {req['condition']}")
                    
    return violations


def _verify_policy_phrases(out_pol: dict, resp_lower: str) -> list[str]:
    """verify_policy with WORD-level matching (config.L5_POLICY_PHRASE_MATCH, v3 code review).

    The rule above tests every word as a SUBSTRING of the whole response: the condition
    "interest rates" held for any text containing "interesting" and "demonstrates", and
    "medical diagnosis" for any letter that says "medical" in one paragraph and "diagnosis" in
    another. Here a disclaimer condition must occur as the PHRASE (whole words, any whitespace),
    and a forbidden topic needs each of its keyword stems at the START of a word ("returns" still
    matches "return", "guarantee" matches "guaranteed"; "rates" no longer matches "demonstrates").
    Measured (scratch/rca/v3/d02): AgentLeak benign policy hits 121 -> 17, WildChat 8 -> 0."""
    import re

    violations = []
    for topic in out_pol.get("forbidden_topics", []) or []:
        keywords = [kw for kw in topic.split("_") if len(kw) > 3]
        if keywords and all(re.search(rf"\b{re.escape(kw)}", resp_lower) for kw in keywords):
            violations.append(f"Forbidden topic detected: {topic}")
    for req in out_pol.get("required_disclaimers", []) or []:
        cond = r"\s+".join(re.escape(w) for w in req["condition"].lower().split())
        if cond and re.search(rf"\b{cond}\b", resp_lower) and req["disclaimer"].lower() not in resp_lower:
            violations.append(f"Missing required disclaimer for condition: {req['condition']}")
    return violations
