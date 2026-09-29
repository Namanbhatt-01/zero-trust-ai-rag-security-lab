import re
import unicodedata
from typing import Optional, Dict
from pydantic import BaseModel

# Known Prompt Injection Signatures & Directives
ADVERSARIAL_DIRECTIVE_PATTERNS = [
    r"(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions",
    r"(?i)system\s+override",
    r"(?i)you\s+are\s+now\s+in\s+(developer|unrestricted|dan|god)\s+mode",
    r"(?i)reveal\s+(all\s+)?(internal|hidden|system)\s+prompts?",
    r"(?i)dump\s+(all\s+)?(vector|database|tenants?|documents?|collections?)",
    r"(?i)disregard\s+(all\s+)?security\s+rules?",
    r"(?i)exfiltrate",
    r"(?i)act\s+as\s+a?\s*root\s+user",
    r"(?i)bypass\s+(rbac|guardrails?|filters?|access\s+controls?)",
    r"(?i)print\s+(all\s+)?(system|internal|config)\s+variables?",
    r"(?i)forget\s+(your\s+)?(instructions|constraints|rules)"
]

# Delimiter Hijack & Escape Patterns
DELIMITER_HIJACK_PATTERNS = [
    r"\[SYSTEM\]",
    r"<\|im_start\|>",
    r"<\|im_end\|>",
    r"```system",
    r"---BEGIN SYSTEM---"
]

# Sensitive Data (PII / PCI / Secrets) Patterns
PII_PATTERNS: Dict[str, str] = {
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "CREDIT_CARD": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    "ROUTING_NUMBER": r"\b\d{9}\b",
    "API_KEY": r"\b(sk-[a-zA-Z0-9]{24,48}|ghp_[a-zA-Z0-9]{36})\b"
}

class GuardrailDecision(BaseModel):
    is_safe: bool
    reason: str = ""
    layer: str = ""
    sanitized_text: str = ""

def normalize_input(text: str) -> str:
    """Normalizes input string by applying Unicode NFKC canonical decomposition
    and stripping hidden/zero-width whitespace characters."""
    if not text:
        return ""
    # Normalize unicode (e.g. Cyrillic/homoglyphs or decomposition)
    normalized = unicodedata.normalize("NFKC", text)
    # Strip zero-width characters (\u200B, \u200C, \u200D, \uFEFF)
    normalized = re.sub(r"[\u200B-\u200D\uFEFF]", "", normalized)
    return normalized

def inspect_prompt_injection(raw_prompt: str) -> GuardrailDecision:
    """Layered prompt injection scanner checking input normalization,
    directive overrides, and delimiter hijack attempts."""
    normalized = normalize_input(raw_prompt)

    # Layer 1: Delimiter & System Tag Hijack Detection
    for pattern in DELIMITER_HIJACK_PATTERNS:
        if re.search(pattern, normalized, re.IGNORECASE):
            return GuardrailDecision(
                is_safe=False,
                reason=f"Security Violation: Delimiter injection tag detected -> '{pattern}'",
                layer="Layer 1: Delimiter Isolation",
                sanitized_text=""
            )

    # Layer 2: Adversarial Directive Pattern Matching
    for pattern in ADVERSARIAL_DIRECTIVE_PATTERNS:
        match = re.search(pattern, normalized)
        if match:
            return GuardrailDecision(
                is_safe=False,
                reason=f"Security Violation: Adversarial prompt injection pattern detected -> '{match.group(0)}'",
                layer="Layer 2: Directive Classifier",
                sanitized_text=""
            )

    return GuardrailDecision(is_safe=True, layer="Guardrail Neutral", sanitized_text=normalized)

def sanitize_pii(text: str) -> str:
    """Redacts sensitive PII/PCI tokens before text is embedded or stored."""
    if not text:
        return ""
    sanitized = text
    for pii_type, pattern in PII_PATTERNS.items():
        sanitized = re.sub(pattern, f"[REDACTED_{pii_type}]", sanitized)
    return sanitized
