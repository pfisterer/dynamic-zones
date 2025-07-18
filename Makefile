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

# Docker Image details
DOCKER_REPO ?= farberg/$(PROJECT_NAME)
DOCKER_TAG ?= latest
DOCKER_PLATFORMS ?= linux/amd64,linux/arm64,linux/arm/v7

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
	$(call npm_install_temp,swagger2openapi @hey-api/openapi-ts esbuild typescript)

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
	@echo "📦 Bundling into a single JS file with esbuild..."
	@mkdir -p $(DIST_DIR)
	set -e; \
	$(NPM_RUN) esbuild "$(CLIENT_TS)" "$(CLIENT_SDK)" --bundle --outdir="$(DIST_DIR)" --format=esm --out-extension:.js=".mjs" --sourcemap
	$(NPM_RUN) esbuild "$(CLIENT_TS)" "$(CLIENT_SDK)" --bundle --outdir="$(DIST_DIR)" --format=cjs --sourcemap
	@echo "✅ Bundled JS in $(DIST_DIR)/"

build: check-modules
	@echo "🔨 Building Go binary..."
	@mkdir -p $(BUILD_DIR)
	@set -e; CGO_ENABLED=1 go build -o $(BUILD_DIR)/$(BINARY_NAME) $(SRC_DIR)/main.go
	@echo "✅ Go binary built (./$(BUILD_DIR)/$(BINARY_NAME))"

check-modules:
	@test -f $(GO_MOD) || (echo "❌ $(GO_MOD) is missing; run 'go mod init' first."; exit 1)

clean:
	@echo "🧹 Cleaning directories..."
	@rm -rf $(BUILD_DIR) $(DOC_DIR) $(CLIENT_DIR) $(NPM_TEMP)
	@echo "✅ Cleanup complete"

run: build
	@echo "🚀 Running the Go app..."
	@./$(BUILD_DIR)/$(BINARY_NAME)

docker-login:
	@echo "🔑 Logging into Docker Hub (or configured registry)..."
	@docker login

docker-build:
	@echo "🏗️ Building Docker image $(DOCKER_REPO):$(DOCKER_TAG)..."
	docker build -t "$(DOCKER_REPO):$(DOCKER_TAG)" .
	@echo "✅ Docker image $(DOCKER_REPO):$(DOCKER_TAG) built."
	@echo "You can push it with: docker push $(DOCKER_REPO):$(DOCKER_TAG)"

multi-arch-build: docker-login
	@echo "🏗️ Building multi-architecture Docker image for $(DOCKER_PLATFORMS)..."
	docker buildx build \
		--platform $(DOCKER_PLATFORMS) \
		--tag "$(DOCKER_REPO):$(DOCKER_TAG)" \
		--push \
		.
	@echo "✅ Multi-architecture image $(DOCKER_REPO):$(DOCKER_TAG) built and pushed."
	@echo "You can pull it with: docker pull $(DOCKER_REPO):$(DOCKER_TAG)"


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
	@echo "  docker-login        → Log into Docker Hub (required before pushing multi-arch images)"
	@echo "  multi-arch-build    → Build and push multi-architecture Docker image (requires buildx & Docker login)"