# KAI Sovereign Anchor Makefile
# ═══════════════════════════════════════════════════════════════

.PHONY: all install build test demo clean help

# Default target
all: install build test

# ═══════════════════════════════════════════════════════════════
# INSTALL
# ═══════════════════════════════════════════════════════════════

install: install-chain install-policy-engine install-vault install-demo
	@echo "✓ All dependencies installed"

install-chain:
	@echo "Installing chain dependencies..."
	cd chain && npm install

install-policy-engine:
	@echo "Installing policy-engine dependencies..."
	cd policy-engine && npm install

install-vault:
	@echo "Installing vault dependencies..."
	cd vault && npm install

install-demo:
	@echo "Installing demo dependencies..."
	cd demo/cli && npm install

# ═══════════════════════════════════════════════════════════════
# BUILD
# ═══════════════════════════════════════════════════════════════

build: build-chain build-policy-engine build-vault
	@echo "✓ All components built"

build-chain:
	@echo "Compiling smart contracts..."
	cd chain && npm run compile

build-policy-engine:
	@echo "Building policy engine..."
	cd policy-engine && npm run build

build-vault:
	@echo "Building vault..."
	cd vault && npm run build

# ═══════════════════════════════════════════════════════════════
# TEST
# ═══════════════════════════════════════════════════════════════

test: test-chain test-policy-engine test-scenarios
	@echo ""
	@echo "═══════════════════════════════════════════════════════════"
	@echo "  ALL TESTS PASSED"
	@echo "═══════════════════════════════════════════════════════════"

test-chain:
	@echo "Running contract tests..."
	cd chain && npm test

test-policy-engine:
	@echo "Running policy engine tests..."
	cd policy-engine && npm test

test-scenarios:
	@echo "Running adversarial scenario tests..."
	cd policy-engine && npm test -- --testPathPattern="PolicyEngine.test.ts" --verbose

# ═══════════════════════════════════════════════════════════════
# DEMO
# ═══════════════════════════════════════════════════════════════

demo: install-demo
	@echo ""
	@echo "Running KAI Sovereign Anchor Demo..."
	@echo ""
	cd demo/cli && npx tsx demo.ts

# ═══════════════════════════════════════════════════════════════
# HASH
# ═══════════════════════════════════════════════════════════════

hash:
	@echo "Computing Core constitution hash..."
	@HASH=$$(sha256sum constitution/core/kai_constitution_core_v1_4.txt | cut -d' ' -f1); \
	echo ""; \
	echo "Core Hash (SHA-256): 0x$$HASH"; \
	echo ""

# ═══════════════════════════════════════════════════════════════
# DEPLOY
# ═══════════════════════════════════════════════════════════════

deploy-local:
	@echo "Starting local Hardhat node..."
	cd chain && npx hardhat node &
	@sleep 3
	@echo "Deploying to local network..."
	cd chain && npm run deploy:local

deploy-sepolia:
	@echo "Deploying to Sepolia testnet..."
	@echo "Make sure chain/.env is configured with SEPOLIA_RPC_URL and PRIVATE_KEY"
	cd chain && npm run deploy:sepolia

verify-receipt:
	@echo "Verifying deployment receipt..."
	cd receipts && npx tsx verify_receipt.ts $(RECEIPT)

# ═══════════════════════════════════════════════════════════════
# CLEAN
# ═══════════════════════════════════════════════════════════════

clean:
	@echo "Cleaning build artifacts..."
	rm -rf chain/artifacts chain/cache chain/typechain-types
	rm -rf policy-engine/dist policy-engine/coverage
	rm -rf vault/dist
	rm -rf demo/cli/dist
	rm -rf node_modules */node_modules
	@echo "✓ Clean complete"

# ═══════════════════════════════════════════════════════════════
# HELP
# ═══════════════════════════════════════════════════════════════

help:
	@echo ""
	@echo "KAI Sovereign Anchor - Available Commands"
	@echo "═══════════════════════════════════════════════════════════"
	@echo ""
	@echo "  make install      Install all dependencies"
	@echo "  make build        Build all components"
	@echo "  make test         Run all tests"
	@echo "  make demo         Run the demonstration"
	@echo "  make hash         Compute Core constitution hash"
	@echo "  make deploy-local   Deploy to local Hardhat network"
	@echo "  make deploy-sepolia Deploy to Sepolia testnet"
	@echo "  make clean        Clean build artifacts"
	@echo ""
	@echo "Individual targets:"
	@echo "  make install-chain         Install chain dependencies"
	@echo "  make install-policy-engine Install policy engine dependencies"
	@echo "  make test-chain            Run contract tests"
	@echo "  make test-policy-engine    Run policy engine tests"
	@echo "  make test-scenarios        Run adversarial scenario tests"
	@echo ""
