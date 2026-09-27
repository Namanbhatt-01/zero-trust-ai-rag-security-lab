import os
import sys
import time
import requests
import subprocess
from datetime import datetime

RAG_URL = os.getenv("RAG_URL", "http://localhost:8000")
QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")

def check_health():
    print("==============================================================================")
    print("                  PHASE 1: STACK INITIALIZATION & HEALTH CHECK                ")
    print("==============================================================================")
    
    # Check Qdrant
    for _ in range(15):
        try:
            r = requests.get(f"{QDRANT_URL}/healthz", timeout=3)
            if r.status_code == 200:
                print("  [+] Qdrant Vector DB (Rust OSS)    -> ONLINE (HTTP 200)")
                break
        except:
            time.sleep(1)
    else:
        print("  [-] Qdrant healthcheck failed!")
        sys.exit(1)

    # Check RAG Gateway
    for _ in range(15):
        try:
            r = requests.get(f"{RAG_URL}/health", timeout=3)
            if r.status_code == 200:
                print("  [+] Zero-Trust RAG Security API    -> ONLINE (HTTP 200)")
                break
        except:
            time.sleep(1)
    else:
        print("  [-] RAG Gateway healthcheck failed!")
        sys.exit(1)

def main():
    check_health()
    
    print("\n==============================================================================")
    print("                  PHASE 2: ADVERSARIAL PENETRATION & RBAC AUDIT               ")
    print("==============================================================================")
    from security_audit.audit_suite import run_security_audit
    run_security_audit()

if __name__ == "__main__":
    main()
