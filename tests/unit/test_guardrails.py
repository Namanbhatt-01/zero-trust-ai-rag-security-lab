import sys
import os
import glob
import yaml
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../rag_service")))

from guardrails import inspect_prompt_injection, sanitize_pii, normalize_input

def test_pii_sanitization_before_embedding():
    raw_text = "Tenant Treasury Wire routing 021000021, SSN 123-45-6789, API key sk-abcdef1234567890abcdef12"
    sanitized = sanitize_pii(raw_text)
    assert "021000021" not in sanitized
    assert "123-45-6789" not in sanitized
    assert "sk-abcdef" not in sanitized
    assert "[REDACTED_ROUTING_NUMBER]" in sanitized
    assert "[REDACTED_SSN]" in sanitized
    assert "[REDACTED_API_KEY]" in sanitized

def test_adversarial_prompt_corpus_eval():
    prompts_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../security/prompts"))
    yaml_files = glob.glob(f"{prompts_dir}/*.yaml")
    assert len(yaml_files) > 0, "No adversarial prompt YAML suites found!"

    total_cases = 0
    for yf in yaml_files:
        with open(yf, "r") as f:
            suite = yaml.safe_load(f)
            for case in suite.get("cases", []):
                total_cases += 1
                decision = inspect_prompt_injection(case["input"])
                assert not decision.is_safe, f"Failed to detect prompt injection for case {case['id']}: {case['input']}"

    assert total_cases >= 8, f"Expected at least 8 adversarial prompt cases, found {total_cases}"
