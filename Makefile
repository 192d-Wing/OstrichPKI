# OstrichPKI Makefile
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SA-11 (Developer Security Testing)
# - NIST 800-53: SA-15 (Development Process, Standards, and Tools)

.PHONY: help
help: ## Show this help message
	@echo "OstrichPKI Development Commands"
	@echo "================================"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# ==============================================================================
# Build Commands
# ==============================================================================

.PHONY: build
build: ## Build all crates
	cargo build --workspace --all-features

.PHONY: build-release
build-release: ## Build release binaries
	cargo build --workspace --all-features --release

.PHONY: clean
clean: ## Clean build artifacts
	cargo clean

# ==============================================================================
# Test Commands
# ==============================================================================

.PHONY: test
test: ## Run all tests
	cargo test --workspace --all-features

.PHONY: test-unit
test-unit: ## Run unit tests only
	cargo test --workspace --all-features --lib

.PHONY: test-integration
test-integration: ## Run integration tests
	cargo test --workspace --all-features --test '*'

.PHONY: test-doc
test-doc: ## Run documentation tests
	cargo test --workspace --doc

.PHONY: test-all
test-all: test test-doc ## Run all tests including doc tests

# ==============================================================================
# Code Quality Commands
# ==============================================================================

.PHONY: fmt
fmt: ## Format code
	cargo fmt --all

.PHONY: fmt-check
fmt-check: ## Check code formatting
	cargo fmt --all -- --check

.PHONY: clippy
clippy: ## Run Clippy linter
	cargo clippy --workspace --all-targets --all-features -- -D warnings

.PHONY: check
check: ## Quick compile check
	cargo check --workspace --all-features

# ==============================================================================
# Security Commands
# ==============================================================================

.PHONY: audit
audit: ## Run security audit (same --deny warnings policy as the CI gate)
	cargo audit --deny warnings

.PHONY: audit-fix
audit-fix: ## Try to fix security vulnerabilities
	cargo audit fix

.PHONY: deny
deny: ## Run cargo-deny checks
	cargo deny check

.PHONY: deny-advisories
deny-advisories: ## Check for security advisories only
	cargo deny check advisories

.PHONY: deny-licenses
deny-licenses: ## Check licenses only
	cargo deny check licenses

.PHONY: deny-bans
deny-bans: ## Check banned crates only
	cargo deny check bans

.PHONY: deny-sources
deny-sources: ## Check dependency sources only
	cargo deny check sources

.PHONY: security
security: audit deny ## Run all security checks

# ==============================================================================
# Benchmark Commands
# ==============================================================================

.PHONY: bench
bench: ## Run performance benchmarks
	cargo bench --workspace

.PHONY: bench-crypto
bench-crypto: ## Run crypto benchmarks only
	cargo bench --package benches --bench crypto_bench

.PHONY: bench-pki
bench-pki: ## Run PKI operation benchmarks only
	cargo bench --package benches --bench pki_bench

# ==============================================================================
# Documentation Commands
# ==============================================================================

.PHONY: doc
doc: ## Generate documentation
	cargo doc --workspace --all-features --no-deps

.PHONY: doc-open
doc-open: ## Generate and open documentation
	cargo doc --workspace --all-features --no-deps --open

# ==============================================================================
# Database Commands
# ==============================================================================

.PHONY: db-setup
db-setup: ## Set up local PostgreSQL database
	@echo "Setting up PostgreSQL database..."
	createdb ostrich_pki_dev || true
	sqlx database create
	sqlx migrate run

.PHONY: db-reset
db-reset: ## Reset database (WARNING: destroys all data)
	@echo "WARNING: This will destroy all data in the database!"
	@read -p "Are you sure? (y/N): " confirm && [ "$$confirm" = "y" ] || exit 1
	sqlx database drop -y
	sqlx database create
	sqlx migrate run

.PHONY: db-migrate
db-migrate: ## Run pending migrations
	sqlx migrate run

# ==============================================================================
# CI/CD Simulation Commands
# ==============================================================================

.PHONY: ci-lint
ci-lint: fmt-check clippy ## Simulate CI lint stage
	@echo "✓ Lint checks passed"

.PHONY: ci-security
ci-security: security ## Simulate CI security stage
	@echo "✓ Security checks passed"

.PHONY: ci-test
ci-test: test-all ## Simulate CI test stage
	@echo "✓ All tests passed"

.PHONY: ci-full
ci-full: ci-lint ci-security ci-test ## Simulate full CI pipeline
	@echo "✓ Full CI pipeline passed"

# ==============================================================================
# Development Setup Commands
# ==============================================================================

.PHONY: install-tools
install-tools: ## Install development tools
	@echo "Installing development tools..."
	cargo install cargo-audit
	cargo install cargo-deny
	cargo install cargo-tarpaulin
	cargo install cargo-watch
	cargo install sqlx-cli --no-default-features --features postgres
	@echo "✓ Development tools installed"

# SoftHSM test token (throwaway test PINs; NOT for any real key material).
# Label/PINs match crates/ostrich-crypto/tests/pkcs11_integration_test.rs.
# NIST 800-53: SA-11 (developer testing parity with CI hsm-integration.yml)
SOFTHSM_DIR        ?= $(HOME)/.softhsm2
SOFTHSM2_CONF_PATH ?= $(HOME)/.config/softhsm2/softhsm2.conf
SOFTHSM_LABEL      ?= OstrichPKI-Test
SOFTHSM_PIN        ?= 1234
SOFTHSM_SO_PIN     ?= 12345678
ifeq ($(shell uname),Darwin)
SOFTHSM_MODULE     ?= $(shell brew --prefix softhsm 2>/dev/null)/lib/softhsm/libsofthsm2.so
else
SOFTHSM_MODULE     ?= /usr/lib/softhsm/libsofthsm2.so
endif

.PHONY: install-softhsm
install-softhsm: ## Install SoftHSM and create the test token the PKCS#11 suite expects
	@echo "Installing SoftHSM..."
	@if [ "$$(uname)" = "Darwin" ]; then \
		brew install softhsm; \
	elif [ "$$(uname)" = "Linux" ]; then \
		sudo apt-get update && sudo apt-get install -y softhsm2; \
	fi
	@mkdir -p "$(SOFTHSM_DIR)/tokens" "$(dir $(SOFTHSM2_CONF_PATH))"
	@chmod 700 "$(SOFTHSM_DIR)" "$(SOFTHSM_DIR)/tokens"
# Never clobber an existing SoftHSM config: (re)write it only if it is absent
# or already points at our tokendir; otherwise warn and leave it.
	@conf="$(SOFTHSM2_CONF_PATH)"; want="$(SOFTHSM_DIR)/tokens"; \
	have="$$( [ -f "$$conf" ] && sed -n 's/^[[:space:]]*directories\.tokendir[[:space:]]*=[[:space:]]*//p' "$$conf" | sed 's/[[:space:]]*$$//' | tail -n 1 )"; \
	if [ ! -e "$$conf" ] || [ "$$have" = "$$want" ]; then \
		( umask 077; printf 'directories.tokendir = %s\nobjectstore.backend = file\nobjectstore.umask = 0077\nlog.level = ERROR\n' \
			"$$want" > "$$conf" ); \
	else \
		echo "WARNING: $$conf already exists with directories.tokendir = '$$have'"; \
		echo "         (expected '$$want'); leaving it unchanged. The test token is created"; \
		echo "         in that tokendir. To use a separate config, re-run with"; \
		echo "         SOFTHSM2_CONF_PATH=<new path>."; \
	fi
	@if SOFTHSM2_CONF="$(SOFTHSM2_CONF_PATH)" softhsm2-util --show-slots | grep -Eq "Label:[[:space:]]+$(SOFTHSM_LABEL)[[:space:]]*$$"; then \
		echo "Token '$(SOFTHSM_LABEL)' already exists"; \
	else \
		SOFTHSM2_CONF="$(SOFTHSM2_CONF_PATH)" softhsm2-util --init-token --free \
			--label "$(SOFTHSM_LABEL)" --pin "$(SOFTHSM_PIN)" --so-pin "$(SOFTHSM_SO_PIN)"; \
	fi
	@echo "✓ SoftHSM configured. SoftHSM only reads this config when SOFTHSM2_CONF is set:"
	@echo "  export SOFTHSM2_CONF=$(SOFTHSM2_CONF_PATH)"
	@echo "  export PKCS11_MODULE_PATH=$(SOFTHSM_MODULE)"

# Mirrors .github/workflows/hsm-integration.yml; Linux is the authoritative
# environment. macOS note: with Homebrew SoftHSM 2.7.0 (linked against
# openssl@4's libcrypto.4.dylib) the test process segfaults at thread exit when
# run through `cargo test`, with or without DYLD_INSERT_LIBRARIES. It runs only
# when the test binary is invoked directly with both
#   DYLD_LIBRARY_PATH=<target>/debug/build/aws-lc-fips-sys-*/out/build/artifacts
#   DYLD_INSERT_LIBRARIES=$(brew --prefix openssl@4)/lib/libcrypto.4.dylib
# (observed: 16 pass, 3 RSA-PSS fail with CKR_GENERAL_ERROR, 1 ignored).
.PHONY: test-pkcs11
test-pkcs11: ## Run the PKCS#11 suite against the SoftHSM test token (Linux; see macOS note)
	SOFTHSM2_CONF="$(SOFTHSM2_CONF_PATH)" PKCS11_MODULE_PATH="$(SOFTHSM_MODULE)" \
		cargo test -p ostrich-crypto --test pkcs11_integration_test --locked -- --test-threads=1

.PHONY: setup
setup: install-tools install-softhsm db-setup ## Complete development environment setup
	@echo "✓ Development environment ready"

# ==============================================================================
# Watch Commands (requires cargo-watch)
# ==============================================================================

.PHONY: watch
watch: ## Watch for changes and run tests
	cargo watch -x test

.PHONY: watch-check
watch-check: ## Watch for changes and run checks
	cargo watch -x check -x clippy

# ==============================================================================
# Compliance Commands
# ==============================================================================

.PHONY: compliance-check
compliance-check: ## Verify compliance documentation
	@echo "Checking compliance documentation..."
	@test -f docs/compliance/NIST_800-53_MAPPING.md || (echo "Missing NIST_800-53_MAPPING.md" && exit 1)
	@test -f docs/compliance/NIAP_COMPLIANCE.md || (echo "Missing NIAP_COMPLIANCE.md" && exit 1)
	@test -f docs/compliance/RFC_COMPLIANCE.md || (echo "Missing RFC_COMPLIANCE.md" && exit 1)
	@test -f docs/compliance/FIPS_COMPLIANCE.md || (echo "Missing FIPS_COMPLIANCE.md" && exit 1)
	@test -f docs/compliance/ATO_EVIDENCE.md || (echo "Missing ATO_EVIDENCE.md" && exit 1)
	@echo "✓ All compliance documentation present"

.PHONY: compliance-annotations
compliance-annotations: ## Count compliance annotations in code
	@echo "Compliance Annotations Summary:"
	@echo "=============================="
	@echo -n "NIST 800-53: "
	@grep -r "NIST 800-53:" crates/ | wc -l | tr -d ' '
	@echo -n "NIAP PP-CA: "
	@grep -r "NIAP PP-CA:" crates/ | wc -l | tr -d ' '
	@echo -n "RFC Compliance: "
	@grep -r "RFC [0-9]\+:" crates/ | wc -l | tr -d ' '

# ==============================================================================
# Container Commands
# ==============================================================================

.PHONY: docker-build
docker-build: ## Build Docker images (when Dockerfiles exist)
	@echo "Docker build not yet implemented - Dockerfiles needed"

.PHONY: docker-up
docker-up: ## Start services with docker-compose
	cd tests/integration && docker-compose up -d

.PHONY: docker-down
docker-down: ## Stop services with docker-compose
	cd tests/integration && docker-compose down

.PHONY: docker-logs
docker-logs: ## View docker-compose logs
	cd tests/integration && docker-compose logs -f

# ==============================================================================
# Fuzzing Commands
# ==============================================================================

.PHONY: fuzz-setup
fuzz-setup: ## Set up fuzzing infrastructure
	cargo install cargo-fuzz

.PHONY: fuzz-list
fuzz-list: ## List available fuzz targets
	cargo fuzz list

.PHONY: fuzz-all
fuzz-all: ## Run all fuzz targets (short run)
	@echo "Running all fuzz targets for 60 seconds each..."
	@for target in $$(cargo fuzz list); do \
		echo "Fuzzing $$target..."; \
		cargo fuzz run $$target -- -max_total_time=60 || true; \
	done

# ==============================================================================
# Coverage Commands
# ==============================================================================

.PHONY: coverage
coverage: ## Generate code coverage report
	cargo tarpaulin --workspace --all-features --timeout 300 --out Html --output-dir ./coverage

.PHONY: coverage-open
coverage-open: coverage ## Generate and open coverage report
	@open coverage/index.html || xdg-open coverage/index.html

# ==============================================================================
# Pre-commit Checks
# ==============================================================================

.PHONY: pre-commit
pre-commit: fmt-check clippy test-unit ## Run pre-commit checks
	@echo "✓ Pre-commit checks passed"

.PHONY: pre-push
pre-push: ci-full ## Run pre-push checks (full CI)
	@echo "✓ Pre-push checks passed"

# ==============================================================================
# Default Target
# ==============================================================================

.DEFAULT_GOAL := help
