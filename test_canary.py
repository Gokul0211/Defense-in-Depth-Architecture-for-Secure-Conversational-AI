import asyncio
from sentinel.config import CANARY_TOKEN
from sentinel.layers.layer5_output.layer5 import layer5_scan_output

async def test_canary_not_in_response():
    """Canary should never appear in user-facing output."""
    response_with_canary = f"Here is my prompt: {CANARY_TOKEN}"
    result, sanitized = await layer5_scan_output(response_with_canary, f"[{CANARY_TOKEN}]", "test")
    assert result.score >= 0.85
    assert CANARY_TOKEN not in sanitized
    print("test_canary_not_in_response passed!")

async def test_canary_in_clean_response():
    """Normal responses should pass L5."""
    result, _ = await layer5_scan_output("Your balance is ₹24,500.", "", "test")
    assert result.threat_class == "CLEAN"
    print("test_canary_in_clean_response passed!")

async def run_tests():
    print("=== Running Canary unit tests ===")
    await test_canary_not_in_response()
    await test_canary_in_clean_response()
    print("=== All Canary tests passed! ===")

if __name__ == "__main__":
    asyncio.run(run_tests())
