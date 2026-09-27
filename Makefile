.PHONY: all up down test audit scan clean

all: up test

up:
	@echo "Starting Zero-Trust RAG Security Stack..."
	docker compose up -d --build

down:
	@echo "Stopping Stack..."
	docker compose down -v --remove-orphans

test:
	@echo "Running Zero-Trust Penetration Audit Suite..."
	python3 verify_rag_security.py

scan:
	@echo "Running Bandit SAST Scan..."
	bash security_audit/bandit_scan.sh

audit: scan test

clean: down
	@echo "Clean complete."
