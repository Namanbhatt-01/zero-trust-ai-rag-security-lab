# Security Incident Post-Mortem & RCA: Cross-Tenant Embedding Leakage in Multi-Tenant RAG

**Incident Reference**: SEC-2026-9904  
**Severity**: P1 - High Risk Data Exposure  
**Affected Service**: Enterprise Multi-Tenant AI Assistant  
**Root Cause**: Post-Retrieval Application Layer Filtering bypassing Vector DB Index Constraints  

---

## 1. Incident Overview

A security audit identified that when users in Tenant Beta queried the enterprise AI copilot with ambiguous finance prompts, the system occasionally returned summary snippets containing Tenant Alpha's proprietary financial contracts. 

Triage revealed that the engineering team had implemented an un-filtered cosine search on the vector database (`limit=50`) followed by a Python-level list comprehension filter `[doc for doc in results if doc.tenant == user.tenant]`. When all top-50 nearest vector neighbors belonged to Tenant Alpha, the application returned empty results, but when a prompt injection payload was introduced, the ranking shifted, occasionally evading downstream text filters.

---

## 2. Technical Remediation & Zero-Trust Architecture

1. **Replaced Post-Retrieval Filter with Native Qdrant HNSW Payload Predicates**: Pushed RBAC predicates directly into Qdrant index search queries.
2. **Introduced Pre-Retrieval Guardrails**: Active regex and heuristic prompt injection interception before vector generation.
3. **Hardened API Authentication**: Enforced JWT cryptographic token validation with immutable tenant claims.
4. **Automated CI/CD Penetration Testing**: Added `security_audit/audit_suite.py` to pull request validation workflows.
