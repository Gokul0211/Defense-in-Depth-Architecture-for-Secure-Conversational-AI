"""
Action authorization (ARCHITECTURE_NEXT.md v2, step 1): intent contract + argument lineage + trust matrix +
global policy. Enabled by config.L4_AUTHZ; combined with L4's existing verdict by taking the stricter one.
"""
from .decide import authorize, AuthzDecision, ALLOW, CONFIRM, BLOCK
from .lineage import record_tool_output, record_call, reset as reset_lineage
from .contract import Contract, set_contract, active_contract, lexicon_contract, llm_contract

__all__ = ["authorize", "AuthzDecision", "ALLOW", "CONFIRM", "BLOCK", "record_tool_output", "record_call",
           "reset_lineage", "Contract", "set_contract", "active_contract", "lexicon_contract", "llm_contract"]
