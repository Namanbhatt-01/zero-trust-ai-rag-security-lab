# Architecture Limitations & Testbed Boundaries

This document defines the explicit engineering boundaries and operational assumptions of this laboratory implementation.

---

## 1. Identity & Credential Boundary
- **Current Mechanism**: The default lab deployment runs against `StaticFixtureIdentityProvider` which maps deterministic bearer tokens to typed `Principal` instances.
- **Limitation**: It does not perform cryptographic asymmetric signature verification against an active OIDC/OAuth2 discovery endpoint (e.g. Keycloak or Okta).
- **Production Path**: In production environments, replace `StaticFixtureIdentityProvider` with `JWTIdentityProvider` configured with public RSA/ECDSA key rotation (`jwks_uri`).

---

## 2. Embedding & Semantic Search Boundary
- **Current Mechanism**: Embeddings are generated using `DeterministicFixtureEmbedding`, which seeds a pseudo-random normal distribution from SHA-256 digests.
- **Limitation**: This produces stable, reproducible vector coordinates for testing vector indexing, distance metrics, graph traversal, and metadata pre-filtering without evaluating semantic relevance or natural language comprehension.
- **Production Path**: For semantic retrieval quality evaluation, implement the `EmbeddingProvider` protocol with a local model (`SentenceTransformerEmbedding`) or cloud provider API.

---

## 3. Ingress Guardrail Boundary
- **Current Mechanism**: Prompt injection detection relies on canonical Unicode normalization (NFKC), delimiter escaping, and regex/directive classification.
- **Limitation**: Regex-based classifiers mitigate known attack signatures and structural overrides, but do not provide semantic intent analysis against novel multi-turn jailbreaks or subtle linguistic steganography.
- **Production Path**: Production architectures deploy a secondary guardrail classifier (e.g. Llama Guard, NeMo Guardrails) in Layer 2 before vectorization.

---

## 4. LLM Generation Boundary
- **Current Mechanism**: This repository tests the **Storage, Ingestion, and Retrieval Isolation Boundary** (the vector security perimeter).
- **Limitation**: It intentionally does not host a multi-billion parameter LLM inference engine on the local developer machine to keep RAM under 1.2 GB.
