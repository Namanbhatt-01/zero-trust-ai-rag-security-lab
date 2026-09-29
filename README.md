# LAB 06: Zero-Trust Multi-Tenant RAG Security & Retrieval Isolation

[![CI/CD Pipeline](https://github.com/Namanbhatt-01/zero-trust-ai-rag-security-lab/actions/workflows/rag_security_ci.yml/badge.svg)](https://github.com/Namanbhatt-01/zero-trust-ai-rag-security-lab/actions/workflows/rag_security_ci.yml)
[![Release](https://img.shields.io/badge/Release-v1.0.0-blue.svg)](https://github.com/Namanbhatt-01/zero-trust-ai-rag-security-lab/releases/tag/v1.0.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A reproducible laboratory for evaluating multi-tenant isolation, RBAC payload pre-filtering, and sanitization boundaries in Retrieval-Augmented Generation (RAG) vector architectures.

---

## 1. Problem Statement

In multi-tenant vector databases, approximate nearest neighbor (ANN) search on an undivided index is permission-blind. If access control is attempted *after* retrieval (filtering top-K results in application code), it suffers from **Top-K Starvation** and computational waste. Furthermore, if sensitive PII or unverified ingestion payloads are vectorized prior to sanitization, vector representations can inadvertently capture protected data.

This laboratory models and validates:
1. **Sanitization-First Ingestion**: PII detection and token masking executed strictly *before* embedding vector calculation.
2. **Atomic Storage Pre-Filtering**: Pushing tenant and role predicates directly into Qdrant's Rust HNSW index engine.
3. **Formal Authorization Policy Engine**: Explicit `Principal` and `Resource` policy gates enforcing boundary and role invariants.
4. **Adversarial Prompt Guardrails**: Multi-layered input normalization, directive interception, and delimiter isolation.

---

## 2. Architecture & Data Flow

```
RAW DOCUMENT ──► CLASSIFICATION ──► PII DETECTION & REDACTION ──► SANITIZED CONTENT
                                                                         │
                                                ┌────────────────────────┘
                                                ▼
                                    DETERMINISTIC EMBEDDING
                                                │
                                                ▼
                                    QDRANT RUST HNSW INDEX
                            (Payload Pre-Filter: tenant_id, allowed_roles)
```

---

## 3. Quickstart & Local Reproduction

### Prerequisites
- Docker / Docker Compose / OrbStack
- Python 3.11+

### Launching the Laboratory
```bash
# Start Qdrant Vector DB and FastAPI RAG Gateway
make up

# Run Unit Tests & Adversarial Prompt Suite
pytest -v tests/unit/

# Run End-to-End Security Invariant Audit
python3 security_audit/audit_suite.py

# Teardown
make down
```

---

## 4. Security Invariant Matrix

The automated security suite (`security_audit/audit_suite.py`) verifies the following invariants:

| Control ID | Security Invariant | Evaluation Method | Result |
| :--- | :--- | :--- | :---: |
| **RAG-SEC-001** | $\forall c \in \text{Results}: c.\text{tenant\_id} \in \{\text{principal.tenant\_id}, \text{public}\}$ | Cross-tenant query simulation | **PASS** |
| **RAG-SEC-002** | $\forall c \in \text{Results}: c.\text{allowed\_roles} \cap \text{principal.roles} \neq \emptyset$ | Role privilege escalation probe | **PASS** |
| **RAG-SEC-003** | Ingestion into foreign tenant space returns HTTP 403 | Forged destination write probe | **PASS** |
| **RAG-SEC-004** | Raw sensitive tokens are never present in vector payloads | PII redaction token verification | **PASS** |
| **RAG-SEC-005** | Direct system override directives return HTTP 400 | Adversarial YAML prompt corpus | **PASS** |
| **RAG-SEC-006** | Unauthenticated and forged tokens rejected with 401/403 | Edge authentication gateway | **PASS** |

---

## 5. Machine-Readable Evidence

Every execution of `security_audit/audit_suite.py` produces a standardized evidence record in `poc/evidence.json`:

```json
{
  "schema_version": "1.0",
  "experiment": {
    "id": "rag-security-001",
    "name": "Zero-Trust Retrieval Isolation and Policy Invariants"
  },
  "execution": {
    "run_id": "rag-2026-09-29-123045",
    "environment": "docker-compose",
    "platform": "darwin-arm64"
  },
  "measurements": [
    { "metric": "cross_tenant_chunks_leaked", "value": 0, "target": 0 }
  ],
  "assertions": [...],
  "result": "passed"
}
```

---

## 6. Known Limitations

Please see [`docs/limitations.md`](docs/limitations.md) for full operational boundaries:
- The default identity provider uses deterministic test fixtures (`StaticFixtureIdentityProvider`).
- The default embedding generator uses deterministic seeded hashing (`DeterministicFixtureEmbedding`) rather than a heavy semantic model to maintain sub-1.2 GB local RAM consumption.
- Prompt injection classification uses pattern and delimiter matching rather than an active semantic safety classifier.

---

## 7. Architecture Decision Records

- [ADR-001: Storage Engine Vector Pre-Filtering vs. Application Post-Filtering](docs/adr/ADR-001-qdrant-payload-pre-filtering.md)

---

## 8. License
This project is licensed under the [MIT License](LICENSE).
