#!/usr/bin/env bash
# ==============================================================================
# Bandit Python Static Application Security Testing (SAST) Scanner
# ==============================================================================

set -euo pipefail

echo "=============================================================================="
echo "          RUNNING BANDIT PYTHON SAST SECURITY AUDIT (OWASP / CWE)             "
echo "=============================================================================="

bandit -r rag_service/ security_audit/ -ll -v || {
    echo "[-] Bandit identified medium/high severity issues!"
    exit 1
}

echo "✅ [PASS] Zero high/medium severity SAST vulnerabilities found in Python code."
