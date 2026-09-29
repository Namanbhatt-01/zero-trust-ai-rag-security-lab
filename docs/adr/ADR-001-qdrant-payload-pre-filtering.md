# ADR-001: Storage Engine Vector Pre-Filtering vs. Application Post-Filtering

## Status
Accepted

## Context
In multi-tenant vector retrieval architectures, multiple tenants store embeddings within a shared vector database. If a user queries the index without access controls, nearest neighbor search (HNSW) evaluates vectors globally, potentially returning confidential vectors from another tenant.

Two approaches were considered:
1. **Application Post-Filtering**: Perform standard top-$K$ search globally, then discard foreign-tenant vectors in Python application code.
2. **Storage Pre-Filtering**: Push deterministic metadata predicates (`must: [tenant_id, allowed_roles]`) directly into Qdrant's Rust HNSW traversal engine.

## Decision
We enforce mandatory **Storage Pre-Filtering** in the Qdrant HNSW engine for all query invocations.

## Consequences & Tradeoffs
- **Positive**: Eliminates Top-$K$ Starvation (where all top-$K$ global results belong to a forbidden tenant, leaving the user with an empty result set).
- **Positive**: Vectors outside the tenant boundary are never scored or traversed, mathematically preventing side-channel data leakage.
- **Negative**: Requires payload indexing in Qdrant memory, adding minor memory overhead per vector point.
