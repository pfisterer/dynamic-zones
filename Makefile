PROJECT_NAME := dynamic-zones
BINARY_NAME := $(PROJECT_NAME)
SRC_DIR := ./cmd
DOC_DIR := ./internal/generated_docs
BUILD_DIR := ./tmp/build
GO_MOD := go.mod

SWAGGER_JSON := $(DOC_DIR)/swagger.json
OPENAPI_YAML := $(DOC_DIR)/openapi3.json
CLIENT_DIR := $(DOC_DIR)/client-typescript
CLIENT_TS := $(CLIENT_DIR)/client.gen.ts
CLIENT_SDK := $(CLIENT_DIR)/sdk.gen.ts
DIST_DIR := $(DOC_DIR)/client-dist
EMBED_FILE := $(DOC_DIR)/embedded.go

# Docker Image details
DOCKER_REPO ?= ghcr.io/pfisterer/$(PROJECT_NAME)
DOCKER_TAG ?= $(shell cat VERSION)
DOCKER_PLATFORMS ?= linux/amd64,linux/arm64

.DEFAULT_GOAL := all

.PHONY: all build clean doc convert client bundle check swag run help install-npm bundle-deps docker docker-login docker-build multi-arch-build dev helm-update

all: bundle build bundle-deps

# Start development server with live reload
dev:
	air

# Install npm dependencies
install-npm:
	@echo "⬇️ Installing npm dependencies..."
	@npm install --silent
	@echo "✅ npm dependencies installed"

# Ensure swag is installed
check-swag:
	@command -v swag >/dev/null 2>&1 || go install github.com/swaggo/swag/cmd/swag@latest

# Generate swagger.json using swag (OpenAPI 2.0)
generate-swagger-json: check-swag
	@echo "📚 Generating swagger.json..."
	@set -e; swag init -g $(SRC_DIR)/main.go -o $(DOC_DIR) --outputTypes json
	@echo "✅ swagger.json generated"

# Convert swagger.json (OpenAPI 2.0) to openapi3.json (OpenAPI 3.0)
convert-to-openapi3: generate-swagger-json install-npm
	@echo "🔁 Converting Swagger 2 → OpenAPI 3..."
	@set -e; \
	npx swagger2openapi $(SWAGGER_JSON) --outfile $(OPENAPI_YAML) --yaml=false --patch --warnOnly
	@echo "✅ OpenAPI v3 spec: $(OPENAPI_YAML)"

# Generate TypeScript client from OpenAPI 3 spec
client: convert-to-openapi3 install-npm
	@echo "📦 Generating TypeScript client..."
	@mkdir -p $(CLIENT_DIR)
	@set -e; \
	npx openapi-ts -i "file://$(abspath $(OPENAPI_YAML))" -o "$(CLIENT_DIR)" -c @hey-api/client-fetch
	rm -f $(OPENAPI_YAML)
	@echo "✅ TS client generated in $(CLIENT_DIR)"

# Bundle web UI dependencies into single JS file and embed into Go
bundle: client install-npm
	@echo "📦 Bundling into a single JS file with esbuild..."
	@mkdir -p $(DIST_DIR)
	set -e; \
	npx esbuild "$(CLIENT_TS)" "$(CLIENT_SDK)" --bundle --outdir="$(DIST_DIR)" --format=esm --out-extension:.js=".mjs" --sourcemap
	npx esbuild "$(CLIENT_TS)" "$(CLIENT_SDK)" --bundle --outdir="$(DIST_DIR)" --format=cjs --sourcemap
	@echo "🧩 Copying VERSION file to $(DOC_DIR)..."
	@cp VERSION $(DOC_DIR)/VERSION
	@echo "🧩 Generating embedded.go for generated docs..."
	@mkdir -p $(DOC_DIR)
	@printf '%s\n' \
		'package generated_docs' \
		'' \
		'import "embed"' \
		'' \
		'//go:embed swagger.json' \
		'var SwaggerJSON string' \
		'//go:embed client-dist/*' \
		'var ClientDist embed.FS' \
		'//go:embed VERSION' \
		'var Version string' \
		> $(EMBED_FILE)
	@echo "✅ Bundled JS in $(DIST_DIR)/"
	@echo "✅ Embedded docs written to $(EMBED_FILE)"
	@echo "Deleting intermediate client files in $(CLIENT_DIR)..."
	@rm -rf $(CLIENT_DIR)
	@echo "✅ Bundled JS in $(DIST_DIR)/"

# Build Go binary
build: check-modules
	@echo "🔨 Building Go binary..."
	@mkdir -p $(BUILD_DIR)
	@set -e; CGO_ENABLED=1 go build -o $(BUILD_DIR)/$(BINARY_NAME) $(SRC_DIR)/main.go
	@echo "✅ Go binary built (./$(BUILD_DIR)/$(BINARY_NAME))"

# Check for go.mod file
check-modules:
	@test -f $(GO_MOD) || (echo "❌ $(GO_MOD) is missing; run 'go mod init' first."; exit 1)

# Clean build and doc directories
clean:
	@echo "🧹 Cleaning directories..."
	@rm -rf $(BUILD_DIR) $(DOC_DIR)
	@echo "✅ Cleanup complete"

# Run the built Go binary
run: build
	@echo "🚀 Running the Go app..."
	@./$(BUILD_DIR)/$(BINARY_NAME)

# Build Docker image
docker-build:
	@echo "🏗️ Building Docker image $(DOCKER_REPO):$(DOCKER_TAG)..."
	docker build --progress=plain -t "$(DOCKER_REPO):$(DOCKER_TAG)" .
	@echo "✅ Docker image $(DOCKER_REPO):$(DOCKER_TAG) built."
	@echo "You can push it with: docker push $(DOCKER_REPO):$(DOCKER_TAG)"

# Run the docker container
docker-run: docker-build
	@echo "🚀 Running Docker container from image $(DOCKER_REPO):$(DOCKER_TAG)..."
	docker run --rm -p 8083:8083 --env-file .env "$(DOCKER_REPO):$(DOCKER_TAG)"

# Build and push multi-architecture Docker image
docker-multi-arch-build: helm-update
	@echo "🏗️ Building multi-architecture Docker image for $(DOCKER_PLATFORMS)..."
	docker buildx build \
		--progress plain \
		--platform $(DOCKER_PLATFORMS) \
		--tag "$(DOCKER_REPO):latest" \
		--tag "$(DOCKER_REPO):$(DOCKER_TAG)" \
		--push \
		.
	@echo "✅ Multi-architecture image $(DOCKER_REPO):$(DOCKER_TAG) built and pushed."
	@echo "You can pull it with: docker pull $(DOCKER_REPO):$(DOCKER_TAG)"

# Update helm chart version from VERSION file
helm-update:
	helm lint helm-chart/
	echo "✅ Helm chart linted successfully."

	@VERSION=$$(cat VERSION | tr -d '\n'); \
	sed -i '' "s/^version: .*/version: $$VERSION/" helm-chart/Chart.yaml; \
	sed -i '' "s/^appVersion: .*/appVersion: \"$$VERSION\"/" helm-chart/Chart.yaml; \
	echo "✅ Updated helm-chart/Chart.yaml to version $$VERSION"

	helm package helm-chart
	mkdir -p docs/helm-repo
	mv cloud-self-service*.tgz docs/helm-repo/
	helm repo index docs/helm-repo --url https://pfisterer.github.io/dynamic-zones/helm-repo
	echo "✅ Helm chart linted successfully."


# Help target
help:
	@echo "Usage: make <target>"
	@echo "  all                     → Build and generate everything"
	@echo "  dev                     → Start development server with live reload (requires air)"
	@echo "  run                     → Run Go app"
	@echo "  build                   → Compile Go binary"
	@echo "  clean                   → Remove build artifacts"
	@echo "  install-npm             → Install npm dependencies from package.json"
	@echo "  check-swag              → Ensure swag is installed"
	@echo "  generate-swagger-json   → Generate swagger.json"
	@echo "  convert-to-openapi3     → Convert swagger.json → openapi3.json"
	@echo "  client                  → Generate TypeScript client"
	@echo "  bundle                  → Bundle client into JS"
	@echo "  bundle-deps             → Bundle web UI dependencies"
	@echo "  docker-build            → Build Docker image"
	@echo "  docker-run              → Run Docker container"
	@echo "  docker-multi-arch-build → Build and push multi-architecture Docker image (requires buildx & Docker login)"
	@echo "  helm-update             → Update Helm chart"