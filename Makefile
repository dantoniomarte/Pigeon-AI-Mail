# Pigeon Mail make targets

.DEFAULT_GOAL := help

.PHONY: help build test lint fmt verify clean install-hooks

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

build: ## Build release binary (requires Rust >= 1.85)
	@if [ -f Cargo.toml ]; then cargo build --release; else echo "backend not initialized yet — see docs/ROADMAP.md"; fi

test: ## Run unit + integration tests
	@if [ -f Cargo.toml ]; then cargo test --workspace; else echo "backend not initialized yet — see docs/ROADMAP.md"; fi

lint: ## clippy + fmt check
	@if [ -f Cargo.toml ]; then cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check; else echo "backend not initialized yet"; fi

fmt: ## Format code
	@if [ -f Cargo.toml ]; then cargo fmt; fi

verify: ## Repo hygiene: secrets, placeholders, template leftovers
	scripts/verify-clean.sh

clean: ## Remove build artifacts
	@if [ -f Cargo.toml ]; then cargo clean; fi
	rm -rf node_modules web/node_modules web/dist

install-hooks: ## Install the pre-push hygiene hook
	@hookdir=$$(git rev-parse --git-path hooks); \
	mkdir -p "$$hookdir"; \
	cp scripts/hooks/pre-push "$$hookdir/pre-push"; \
	chmod +x "$$hookdir/pre-push"; \
	echo "installed pre-push hook in $$hookdir"

run-local: ## Build webmail + binary and start a local server on :8000 (demo DB in /tmp/pigeon-local)
	@cd web && npm run build
	@mkdir -p /tmp/pigeon-local && rm -rf /tmp/pigeon-local/web && cp -r web/dist /tmp/pigeon-local/web
	@pkill -f 'target/release/pigeon' 2>/dev/null || true
	@sleep 1
	@PIGEON_MASTER_KEY_FILE=/tmp/pigeon-local/master.key PIGEON_DB_PATH=/tmp/pigeon-local/pigeon.db \
		PIGEON_HTTP_ADDR=127.0.0.1:8000 PIGEON_SMTP_IN_ADDR=127.0.0.1:2525 \
		PIGEON_SMTP_OUT_ADDR=127.0.0.1:2525 PIGEON_SMTP_OUT_STARTTLS=opportunistic \
		PIGEON_SMTP_HOSTNAME=pigeon.local PIGEON_WEBMAIL=on \
		PIGEON_WEBMAIL_DIR=/tmp/pigeon-local/web \
		setsid nohup ./target/release/pigeon serve >> /tmp/pigeon-local/server.log 2>&1 < /dev/null &
	@sleep 2 && curl -s http://127.0.0.1:8000/healthz && echo " · pigeon local ready on :8000"
