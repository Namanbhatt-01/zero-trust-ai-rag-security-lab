#!/usr/bin/env bash
# ==============================================================================
# Lab 5: Zero-Trust AI RAG Security Audit Runner
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

echo "=============================================================================="
echo "    LAB 5: ZERO-TRUST AI RAG SECURITY & RBAC PENETRATION AUDIT                "
echo "=============================================================================="
echo "[+] Starting Qdrant Vector DB and Secure RAG Gateway containers..."

docker compose up -d --build

echo "[+] Waiting for services to converge..."
for i in {1..20}; do
    if curl -s http://localhost:6333/healthz >/dev/null 2>&1 && curl -s http://localhost:8000/health >/dev/null 2>&1; then
        echo "[+] Stack is healthy and responsive."
        break
    fi
    sleep 1
done

echo ""
echo "[+] Running Static Application Security Testing (Bandit)..."
bash security_audit/bandit_scan.sh

echo ""
echo "[+] Running Automated Adversarial Penetration Test Suite..."
python3 verify_rag_security.py

echo ""
echo "=============================================================================="
echo "🎉 ZERO-TRUST AI RAG SECURITY AUDIT COMPLETED SUCCESSFULLY!"
echo "   - Qdrant Vector DB: http://localhost:6333/dashboard"
echo "   - RAG Gateway API:  http://localhost:8000/docs"
echo "=============================================================================="
