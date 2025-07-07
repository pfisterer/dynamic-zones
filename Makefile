PROJECT_NAME := dynamic-zones
BINARY_NAME := $(PROJECT_NAME)
SRC_DIR := ./cmd
DOC_DIR := docs
BUILD_DIR := build
GO_MOD := go.mod

SWAGGER_JSON := $(DOC_DIR)/swagger.json
OPENAPI_YAML := $(DOC_DIR)/openapi3.json
CLIENT_DIR := $(DOC_DIR)/client-typescript
CLIENT_TS := $(CLIENT_DIR)/client.gen.ts
CLIENT_SDK := $(CLIENT_DIR)/sdk.gen.ts
DIST_DIR := $(DOC_DIR)/client-dist
NPM_TEMP := $(PWD)/.npm-temp

# Macro to install npm packages temporarily
define npm_install_temp
	@echo "⬇️ Installing npm packages temporarily: $(1)..."; \
	mkdir -p "$(NPM_TEMP)"; \
	npm install --no-save --prefix "$(NPM_TEMP)" $(1) >/dev/null
endef

# Shortcut to run local temporary npm tools
NPM_RUN = npx --no-install --prefix $(NPM_TEMP)

.DEFAULT_GOAL := all

.PHONY: all build clean doc convert client bundle check swag run help

all: bundle build

check-npm-tools:
	$(call npm_install_temp,swagger2openapi @hey-api/openapi-ts tsup typescript)

check-swag:
	@command -v swag >/dev/null 2>&1 || go install github.com/swaggo/swag/cmd/swag@latest

doc: check-swag
	@echo "📚 Generating swagger.json..."
	@set -e; swag init -g $(SRC_DIR)/main.go -o $(DOC_DIR)
	@echo "✅ swagger.json generated"

convert: doc check-npm-tools
	@echo "🔁 Converting Swagger 2 → OpenAPI 3..."
	@set -e; \
	$(NPM_RUN) swagger2openapi $(SWAGGER_JSON) \
		--outfile $(OPENAPI_YAML) --yaml=false --patch --warnOnly
	@echo "✅ OpenAPI v3 spec: $(OPENAPI_YAML)"

client: convert check-npm-tools
	@echo "📦 Generating TypeScript client..."
	@mkdir -p $(CLIENT_DIR)
	@set -e; \
	$(NPM_RUN) openapi-ts -i "$(OPENAPI_YAML)" -o "$(CLIENT_DIR)" -c @hey-api/client-fetch
	@echo "✅ TS client at $(CLIENT_TS)"

bundle: client check-npm-tools
	@echo "📦 Bundling into a single JS file..."
	@mkdir -p $(DIST_DIR)
	set -e; \
	$(NPM_RUN) tsup "$(CLIENT_TS)" "$(CLIENT_SDK)" --format esm,cjs --out-dir "$(DIST_DIR)" --sourcemap
	@echo "✅ Bundled JS in $(DIST_DIR)/"

build: check-modules
	@echo "🔨 Building Go binary..."
	@mkdir -p $(BUILD_DIR)
	@set -e; go build -o $(BUILD_DIR)/$(BINARY_NAME) $(SRC_DIR)/main.go
	@echo "✅ Go binary built (./$(BUILD_DIR)/$(BINARY_NAME))"

check-modules:
	@test -f $(GO_MOD) || (echo "❌ $(GO_MOD) is missing; run 'go mod init' first."; exit 1)

clean:
	@echo "🧹 Cleaning directories..."
	@rm -rf $(BUILD_DIR) $(DOC_DIR) $(CLIENT_DIR) $(DIST_DIR) $(NPM_TEMP)
	@echo "✅ Cleanup complete"

run: build
	@echo "🚀 Running the Go app..."
	@./$(BUILD_DIR)/$(BINARY_NAME)

help:
	@echo "Usage: make <target>"
	@echo "  all       → Build and generate everything"
	@echo "  doc       → Generate swagger.json"
	@echo "  convert   → Convert swagger.json → openapi.json"
	@echo "  client    → Generate TypeScript client"
	@echo "  bundle    → Bundle client into JS"
	@echo "  build     → Compile Go binary"
	@echo "  clean     → Remove build artifacts"
	@echo "  run       → Run Go app"
