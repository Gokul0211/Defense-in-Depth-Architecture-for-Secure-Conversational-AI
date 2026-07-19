TOOL_RISK_MATRIX = {
    "read_file": {"base_risk": "LOW", "elevated_triggers": ["../", "/etc/"]},
    "web_search": {"base_risk": "LOW", "elevated_triggers": ["internal", "localhost", "127.0.0.1", "corp"]},
    "send_email": {"base_risk": "HIGH", "elevated_triggers": []},
    "send_email_bulk": {"base_risk": "CRITICAL", "elevated_triggers": []},
    "execute_code": {"base_risk": "CRITICAL", "elevated_triggers": []},
    "api_call_get": {"base_risk": "MEDIUM", "elevated_triggers": []},
    "api_call_post": {"base_risk": "HIGH", "elevated_triggers": []},
    "database_write": {"base_risk": "CRITICAL", "elevated_triggers": []},
    "delete": {"base_risk": "CRITICAL", "elevated_triggers": []},
    "delete_file": {"base_risk": "CRITICAL", "elevated_triggers": []},
    "modify_system": {"base_risk": "CRITICAL", "elevated_triggers": []},
    "create_user": {"base_risk": "HIGH", "elevated_triggers": []},
    "get_weather": {"base_risk": "LOW", "elevated_triggers": []},
    "calculate": {"base_risk": "LOW", "elevated_triggers": []},
    "refund_api": {"base_risk": "HIGH", "elevated_triggers": []}, # Specific for demo scenario
    "approve_loan": {"base_risk": "CRITICAL", "elevated_triggers": []},
}

def evaluate_tool_risk(tool_name: str, parameters: dict) -> str:
    """Evaluate base risk of a tool call and check for elevated triggers."""
    tool_info = TOOL_RISK_MATRIX.get(tool_name, {"base_risk": "MEDIUM", "elevated_triggers": []})
    current_risk = tool_info["base_risk"]
    
    # Check for elevated risk triggers in parameters
    param_str = str(parameters).lower()
    for trigger in tool_info["elevated_triggers"]:
        if trigger in param_str:
            return "CRITICAL" # Escalate to critical if trigger found
            
    return current_risk

def risk_to_score(risk_level: str) -> float:
    """Convert risk string to 0-1 score."""
    return {"LOW": 0.2, "MEDIUM": 0.5, "HIGH": 0.8, "CRITICAL": 1.0}.get(risk_level, 0.5)
