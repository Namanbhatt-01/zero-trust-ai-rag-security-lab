import os
import sys
import json
import time
import hashlib
from typing import List, Optional
from fastapi import FastAPI, Header, HTTPException, Depends, status
from pydantic import BaseModel
from qdrant_client import QdrantClient
from qdrant_client.http import models

from auth import Principal, IdentityProvider, StaticFixtureIdentityProvider
from policy import Resource, PolicyGate, PolicyDecision
from embeddings import EmbeddingProvider, DeterministicFixtureEmbedding
from guardrails import inspect_prompt_injection, sanitize_pii

QDRANT_HOST = os.getenv("QDRANT_HOST", "qdrant")
QDRANT_PORT = int(os.getenv("QDRANT_PORT", "6333"))
COLLECTION_NAME = "enterprise_rag_vectors"
VECTOR_DIM = 128

app = FastAPI(
    title="Zero-Trust Multi-Tenant RAG Security Gateway",
    version="1.0.0",
    description="Containerized secure RAG gateway enforcing RBAC vector metadata pre-filtering, prompt injection defense, and sanitized PII embeddings."
)

# Instantiate core architectural providers
identity_provider: IdentityProvider = StaticFixtureIdentityProvider()
embedding_provider: EmbeddingProvider = DeterministicFixtureEmbedding(vector_dim=VECTOR_DIM)

# In-memory security telemetry metrics
class SecurityMetrics:
    def __init__(self):
        self.total_queries = 0
        self.prompt_injections_blocked = 0
        self.cross_tenant_access_denied = 0
        self.unauthenticated_attempts_blocked = 0
        self.pii_redactions_performed = 0

metrics = SecurityMetrics()

def get_qdrant_client() -> QdrantClient:
    return QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT, timeout=10)

def authenticate_request(authorization: Optional[str] = Header(None)) -> Principal:
    """Authenticates caller against the IdentityProvider interface."""
    if not authorization or not authorization.startswith("Bearer "):
        metrics.unauthenticated_attempts_blocked += 1
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: Missing or malformed Bearer token."
        )
    token = authorization.split(" ")[1]
    principal = identity_provider.authenticate(token)
    if not principal:
        metrics.unauthenticated_attempts_blocked += 1
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authentication failed: Invalid or expired API credentials."
        )
    return principal

class IngestDoc(BaseModel):
    doc_id: str
    title: str
    tenant_id: str
    classification: str = "INTERNAL"
    allowed_roles: List[str] = ["*"]
    content: str

class QueryRequest(BaseModel):
    query: str
    target_tenant_hint: Optional[str] = None
    top_k: int = 3

@app.on_event("startup")
def init_vector_collection():
    print(f"[*] Initializing Qdrant connection to {QDRANT_HOST}:{QDRANT_PORT}...")
    client = get_qdrant_client()
    for _ in range(30):
        try:
            collections = client.get_collections().collections
            exists = any(c.name == COLLECTION_NAME for c in collections)
            if not exists:
                print(f"[+] Creating Qdrant collection '{COLLECTION_NAME}' (dim: {VECTOR_DIM})...")
                client.create_collection(
                    collection_name=COLLECTION_NAME,
                    vectors_config=models.VectorParams(size=VECTOR_DIM, distance=models.Distance.COSINE)
                )
            print(f"[+] Collection '{COLLECTION_NAME}' is ready.")
            break
        except Exception as e:
            print(f"[-] Awaiting Qdrant readiness ({e})...")
            time.sleep(1)

    # Auto-index seed datasets from data directory
    data_dir = "/app/data" if os.path.exists("/app/data") else "rag_service/data"
    if os.path.exists(data_dir):
        import glob
        print(f"[*] Auto-indexing multi-tenant seed documents from {data_dir}...")
        for fpath in glob.glob(f"{data_dir}/*.json"):
            try:
                with open(fpath, "r") as f:
                    docs = json.load(f)
                    points = []
                    for i, doc in enumerate(docs):
                        # Security Invariant: Raw content is sanitized BEFORE embedding!
                        raw_content = doc.get("content", "")
                        sanitized_content = sanitize_pii(raw_content)
                        if sanitized_content != raw_content:
                            metrics.pii_redactions_performed += 1

                        # Vector is computed strictly from sanitized text
                        vec = embedding_provider.embed(sanitized_content)
                        pt_id = int(hashlib.sha256(f"{doc.get('tenant_id')}_{doc.get('doc_id')}_{i}".encode()).hexdigest()[:8], 16)
                        points.append(models.PointStruct(
                            id=pt_id,
                            vector=vec,
                            payload={
                                "doc_id": doc.get("doc_id"),
                                "title": doc.get("title"),
                                "tenant_id": doc.get("tenant_id"),
                                "classification": doc.get("classification"),
                                "allowed_roles": doc.get("allowed_roles"),
                                "content": sanitized_content
                            }
                        ))
                    if points:
                        client.upsert(collection_name=COLLECTION_NAME, points=points)
                        print(f"  [+] Seeded {len(points)} documents from {fpath}")
            except Exception as e:
                print(f"[-] Seed error for {fpath}: {e}")

@app.post("/api/v1/ingest")
def ingest_documents(docs: List[IngestDoc], principal: Principal = Depends(authenticate_request)):
    client = get_qdrant_client()
    points = []

    for i, doc in enumerate(docs):
        resource = Resource(
            doc_id=doc.doc_id,
            tenant_id=doc.tenant_id,
            classification=doc.classification,
            allowed_roles=doc.allowed_roles
        )

        # Policy Gate: Enforce ingestion boundary and writer privilege
        decision = PolicyGate.can_ingest(principal, resource)
        if not decision.allowed:
            metrics.cross_tenant_access_denied += 1
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Authorization Violation [{decision.control_id}]: {decision.reason}"
            )

        # Ingestion Pipeline: PII detection -> Sanitization -> Embedding -> Vector DB
        sanitized_content = sanitize_pii(doc.content)
        if sanitized_content != doc.content:
            metrics.pii_redactions_performed += 1

        # Embed SANITIZED text (never raw PII)
        vec = embedding_provider.embed(sanitized_content)
        pt_id = int(hashlib.sha256(f"{doc.tenant_id}_{doc.doc_id}_{i}".encode()).hexdigest()[:8], 16)

        points.append(models.PointStruct(
            id=pt_id,
            vector=vec,
            payload={
                "doc_id": doc.doc_id,
                "title": doc.title,
                "tenant_id": doc.tenant_id,
                "classification": doc.classification,
                "allowed_roles": doc.allowed_roles,
                "content": sanitized_content
            }
        ))

    client.upsert(collection_name=COLLECTION_NAME, points=points)
    return {"status": "INGESTED", "count": len(points), "principal": principal.subject}

@app.post("/api/v1/query")
def secure_rag_query(req: QueryRequest, principal: Principal = Depends(authenticate_request)):
    metrics.total_queries += 1

    # Layer 1 & 2 Guardrails: Normalization & Prompt Injection Interception
    injection_check = inspect_prompt_injection(req.query)
    if not injection_check.is_safe:
        metrics.prompt_injections_blocked += 1
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=injection_check.reason)

    # Layer 3 Guardrails: Tenant Boundary Validation via PolicyGate
    query_policy = PolicyGate.can_query(principal, req.target_tenant_hint)
    if not query_policy.allowed:
        metrics.cross_tenant_access_denied += 1
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=query_policy.reason)

    # Layer 4 Guardrails: Vector Embedding & Atomic HNSW Predicate Pre-Filtering
    query_vector = embedding_provider.embed(injection_check.sanitized_text)
    client = get_qdrant_client()

    # Invariant: Pre-filter strictly restricts search graph to Principal's tenant and assigned roles
    role_matches = list(principal.roles) + ["*"]
    rbac_filter = models.Filter(
        must=[
            models.FieldCondition(
                key="tenant_id",
                match=models.MatchAny(any=[principal.tenant_id, "public"])
            ),
            models.FieldCondition(
                key="allowed_roles",
                match=models.MatchAny(any=role_matches)
            )
        ]
    )

    results = client.search(
        collection_name=COLLECTION_NAME,
        query_vector=query_vector,
        query_filter=rbac_filter,
        limit=req.top_k
    )

    retrieved_chunks = []
    for hit in results:
        payload = hit.payload or {}
        chunk_resource = Resource(
            doc_id=payload.get("doc_id", ""),
            tenant_id=payload.get("tenant_id", ""),
            classification=payload.get("classification", "INTERNAL"),
            allowed_roles=payload.get("allowed_roles", ["*"])
        )

        # Defense-in-depth: Double-check clearance level post-retrieval
        if PolicyGate.is_chunk_authorized(principal, chunk_resource):
            retrieved_chunks.append({
                "doc_id": payload.get("doc_id"),
                "title": payload.get("title"),
                "tenant_id": payload.get("tenant_id"),
                "classification": payload.get("classification"),
                "allowed_roles": payload.get("allowed_roles"),
                "similarity_score": round(hit.score, 4),
                "content": payload.get("content")
            })

    return {
        "principal": {
            "subject": principal.subject,
            "tenant_id": principal.tenant_id,
            "roles": list(principal.roles),
            "clearance": principal.clearance
        },
        "query": req.query,
        "retrieved_chunks_count": len(retrieved_chunks),
        "results": retrieved_chunks
    }

@app.get("/api/v1/security-metrics")
def get_security_metrics():
    return {
        "total_queries": metrics.total_queries,
        "prompt_injections_blocked": metrics.prompt_injections_blocked,
        "cross_tenant_access_denied": metrics.cross_tenant_access_denied,
        "unauthenticated_attempts_blocked": metrics.unauthenticated_attempts_blocked,
        "pii_redactions_performed": metrics.pii_redactions_performed
    }

@app.get("/health")
def health_check():
    return {"status": "HEALTHY", "service": "Zero-Trust RAG Security Gateway"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)  # nosec B104
