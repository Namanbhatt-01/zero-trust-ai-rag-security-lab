import re
import typing

INJECTION_PATTERNS = [
    r"(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions",
    r"(?i)system\s+override",
    r"(?i)you\s+are\s+now\s+in\s+(developer|unrestricted|dan)\s+mode",
    r"(?i)reveal\s+(all\s+)?(internal|hidden|system)\s+prompts?",
    r"(?i)dump\s+(all\s+)?(vector|database|tenants?|documents?)",
    r"(?i)disregard\s+security\s+rules?",
    r"(?i)exfiltrate",
    r"(?i)act\s+as\s+a\s+root\s+user",
    r"(?i)bypass\s+(rbac|guardrails?|filters?)"
]

PII_PATTERNS = {
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "CREDIT_CARD": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    "ROUTING_NUMBER": r"\b\d{9}\b",
    "API_KEY": r"\b(sk-[a-zA-Z0-9]{24,48}|ghp_[a-zA-Z0-9]{36})\b"
}

class GuardrailResult:
    def __init__(self, is_safe: bool, reason: str = "", sanitized_text: str = ""):
        self.is_safe = is_safe
        self.reason = reason
        self.sanitized_text = sanitized_text

def inspect_prompt_injection(user_prompt: str) -> GuardrailResult:
    """Scans incoming user query for adversarial prompt injection and jailbreak signatures."""
    for pattern in INJECTION_PATTERNS:
        match = re.search(pattern, user_prompt)
        if match:
            return GuardrailResult(
                is_safe=False,
                reason=f"Security Violation: Adversarial prompt injection pattern detected -> '{match.group(0)}'",
                sanitized_text=""
            )
    return GuardrailResult(is_safe=True, sanitized_text=user_prompt)

def sanitize_pii(text: str) -> str:
    """Redacts PII (SSNs, Card Numbers, API keys) before ingestion or output generation."""
    sanitized = text
    for pii_type, pattern in PII_PATTERNS.items():
        sanitized = re.sub(pattern, f"[REDACTED_{pii_type}]", sanitized)
    return sanitized

def validate_tenant_query(user_tenant_id: str, requested_tenant: typing.Optional[str]) -> GuardrailResult:
    """Enforces zero-trust tenant boundary: users cannot request data outside their assigned tenant."""
    if requested_tenant and requested_tenant != "public" and requested_tenant != user_tenant_id:
        return GuardrailResult(
            is_safe=False,
            reason=f"Access Denied: Tenant '{user_tenant_id}' is not authorized to query tenant '{requested_tenant}' vectors.",
            sanitized_text=""
        )
    return GuardrailResult(is_safe=True)
