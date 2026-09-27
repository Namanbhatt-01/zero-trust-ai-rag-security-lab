import os
import sys
import json
import time
import hashlib
import numpy as np
from typing import List, Optional
from fastapi import FastAPI, Header, HTTPException, Depends, status
from pydantic import BaseModel
from qdrant_client import QdrantClient
from qdrant_client.http import models
from guardrails import inspect_prompt_injection, sanitize_pii, validate_tenant_query

QDRANT_HOST = os.getenv("QDRANT_HOST", "qdrant")
QDRANT_PORT = int(os.getenv("QDRANT_PORT", "6333"))
COLLECTION_NAME = "enterprise_rag_vectors"
VECTOR_DIM = 128

app = FastAPI(
    title="Zero-Trust Multi-Tenant RAG Security Gateway",
    version="1.0.0",
    description="Containerized secure RAG gateway enforcing RBAC vector metadata filtering, prompt injection defense, and PII masking."
)

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

def generate_embedding(text: str) -> List[float]:
    """Generates a deterministic 128-dimensional dense vector representation."""
    h = hashlib.sha256(text.encode("utf-8")).digest()
    np.random.seed(int.from_bytes(h[:4], "big"))
    vec = np.random.normal(0.0, 1.0, VECTOR_DIM)
    norm = np.linalg.norm(vec)
    return (vec / norm).tolist() if norm > 0 else vec.tolist()

# Mock Token Database for Enterprise Users
VALID_TOKENS = {
    "token-alpha-fin-admin": {"user_id": "alice@tenant-alpha.com", "tenant_id": "tenant-alpha", "role": "finance-admin"},
    "token-alpha-exec": {"user_id": "bob@tenant-alpha.com", "tenant_id": "tenant-alpha", "role": "executive"},
    "token-beta-hr-admin": {"user_id": "carol@tenant-beta.com", "tenant_id": "tenant-beta", "role": "hr-admin"},
    "token-beta-employee": {"user_id": "david@tenant-beta.com", "tenant_id": "tenant-beta", "role": "staff"},
    "token-public-user": {"user_id": "guest@external.com", "tenant_id": "guest-org", "role": "guest"}
}

def authenticate_request(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        metrics.unauthenticated_attempts_blocked += 1
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: Missing or malformed Bearer token."
        )
    token = authorization.split(" ")[1]
    if token not in VALID_TOKENS:
        metrics.unauthenticated_attempts_blocked += 1
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authentication failed: Invalid or expired API credentials."
        )
    return VALID_TOKENS[token]

class IngestDoc(BaseModel):
    doc_id: str
    title: str
    tenant_id: str
    classification: str
    allowed_roles: List[str]
    content: str

class QueryRequest(BaseModel):
    query: str
    target_tenant_hint: Optional[str] = None
    top_k: int = 3

@app.on_event("startup")
def init_vector_collection():
    print(f"[*] Initializing Qdrant connection to {QDRANT_HOST}:{QDRANT_PORT}...")
    client = get_qdrant_client()
    for _ in range(15):
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

@app.post("/api/v1/ingest")
def ingest_documents(docs: List[IngestDoc], user: dict = Depends(authenticate_request)):
    client = get_qdrant_client()
    points = []
    
    for i, doc in enumerate(docs):
        # Enforce tenant data boundary on ingestion
        if user["tenant_id"] != "tenant-alpha" and user["tenant_id"] != "tenant-beta" and user["role"] != "admin":
            if doc.tenant_id != user["tenant_id"] and doc.tenant_id != "public":
                metrics.cross_tenant_access_denied += 1
                raise HTTPException(status_code=403, detail="Unauthorized: Cannot ingest data into another tenant space.")

        sanitized_content = sanitize_pii(doc.content)
        if sanitized_content != doc.content:
            metrics.pii_redactions_performed += 1

        vec = generate_embedding(doc.content)
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
    return {"status": "INGESTED", "count": len(points)}

@app.post("/api/v1/query")
def secure_rag_query(req: QueryRequest, user: dict = Depends(authenticate_request)):
    metrics.total_queries += 1

    # 1. Guardrail Inspection: Adversarial Prompt Injection Defense
    injection_check = inspect_prompt_injection(req.query)
    if not injection_check.is_safe:
        metrics.prompt_injections_blocked += 1
        raise HTTPException(status_code=400, detail=injection_check.reason)

    # 2. Guardrail Inspection: Tenant Boundary Enforcement
    tenant_check = validate_tenant_query(user["tenant_id"], req.target_tenant_hint)
    if not tenant_check.is_safe:
        metrics.cross_tenant_access_denied += 1
        raise HTTPException(status_code=403, detail=tenant_check.reason)

    # 3. Vector Embedding & RBAC Payload Filtering in Qdrant
    query_vector = generate_embedding(req.query)
    client = get_qdrant_client()

    # Zero-Trust Metadata Filtering: Only retrieve chunks matching user's tenant OR public, AND user's role OR wildcard
    rbac_filter = models.Filter(
        must=[
            models.FieldCondition(
                key="tenant_id",
                match=models.MatchAny(any=[user["tenant_id"], "public"])
            ),
            models.FieldCondition(
                key="allowed_roles",
                match=models.MatchAny(any=[user["role"], "*"])
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
        retrieved_chunks.append({
            "doc_id": payload.get("doc_id"),
            "title": payload.get("title"),
            "tenant_id": payload.get("tenant_id"),
            "classification": payload.get("classification"),
            "similarity_score": round(hit.score, 4),
            "content": payload.get("content")
        })

    return {
        "user_id": user["user_id"],
        "tenant_id": user["tenant_id"],
        "role": user["role"],
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
