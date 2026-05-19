# VeriCTI-RAG Makefile
# Run common tasks with: make <target>

.PHONY: test demo professor-demo ui api install install-full clean help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install minimal dependencies (tests + demo, offline)
	pip install -r requirements-min.txt

install-full: ## Install full dependencies (UI + vector DB + embeddings)
	pip install -r requirements-full.txt

test: ## Run all unit tests
	python -m pytest -q

demo: ## Run the standard end-to-end demo
	python run_demo.py

professor-demo: ## Run the polished professor demo (Phase 1)
	python run_professor_demo.py --json

api: ## Start the FastAPI backend on port 8000
	uvicorn app.main:app --reload --port 8000

ui: ## Start the Streamlit frontend
	streamlit run frontend/streamlit_app.py

clean: ## Remove caches and generated database
	rm -rf .pytest_cache __pycache__ app/__pycache__
	rm -f data/vericti.db
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
