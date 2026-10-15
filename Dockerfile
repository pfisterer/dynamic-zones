## Stage 1: Builder image
# The build stage runs on the machine that builds (BUILDPLATFORM) and cross-compiles for the target: on an arm64 Mac that is native speed instead of emulation. The SQLite driver needs cgo, so the C side is cross-compiled too, with tonistiigi/xx (xx-go sets GOOS, GOARCH and a clang for the target; xx-apk installs the target's libraries).
FROM --platform=$BUILDPLATFORM tonistiigi/xx:1.6.1 AS xx
# Base images are pinned to exact versions (Go 1.27.2 for its security fixes; the runtime Alpine to a point release), so a rebuild produces the image that was reviewed and a new base arrives as a visible change, not as a side effect.
FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine3.24 AS builder
COPY --from=xx / /
ARG TARGETPLATFORM

# Tools for the build machine; gcc, musl and SQLite for the target
RUN apk add --no-cache git nodejs npm make clang lld
RUN xx-apk add --no-cache gcc musl-dev sqlite-dev

# Set the Current Working Directory inside the container
WORKDIR /app

# Download Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy JS dependencies and build frontend assets
COPY package.json package-lock.json ./

# Copy the source code from the current directory to the Working Directory inside the container
COPY Makefile ./
COPY VERSION ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/

# Build the application
RUN BUILD_GO=xx-go make all && xx-verify tmp/build/dynamic-zones

## Stage 2: Production image
FROM alpine:3.24.2 AS final

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/tmp/build/dynamic-zones /app/

# Expose port
EXPOSE 8082

# Command to run the executable
# Run as a non-root user (numeric UID so Kubernetes can enforce runAsNonRoot
# without resolving names). Nothing in this image is written at runtime; the
# binary only needs to be readable and executable.
USER 65532:65532

CMD ["./dynamic-zones"]