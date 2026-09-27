import os
import json
import glob
import requests
import time

RAG_URL = os.getenv("RAG_URL", "http://localhost:8000")
DATA_DIR = os.getenv("DATA_DIR", "/app/data" if os.path.exists("/app/data") else "rag_service/data")

def ingest_all():
    print(f"[*] Ingesting Enterprise Multi-Tenant Documents from {DATA_DIR}...")
    token = "token-alpha-fin-admin" # authorized admin token
    
    json_files = glob.glob(f"{DATA_DIR}/*.json")
    total_docs = 0

    for file_path in json_files:
        with open(file_path, "r") as f:
            docs = json.load(f)
            resp = requests.post(
                f"{RAG_URL}/api/v1/ingest",
                json=docs,
                headers={"Authorization": f"Bearer {token}"},
                timeout=10
            )
            print(f"  [+] Ingested {file_path}: {resp.json()}")
            total_docs += len(docs)

    print(f"[*] Total {total_docs} multi-tenant documents successfully indexed into Qdrant.")

if __name__ == "__main__":
    time.sleep(2)
    ingest_all()
