## Stage 1: Builder image
FROM golang:1-alpine AS builder

# Install git, nodejs, npm, and make using Alpine's apk package manager
RUN apk add --no-cache git nodejs npm make build-base sqlite-dev

# Set the Current Working Directory inside the container
WORKDIR /app

# Download Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code from the current directory to the Working Directory inside the container
COPY . .

# Build the application
RUN make all

## Stage 2: Production image
FROM alpine:latest AS final

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/tmp/build/dynamic-zones /app/

# Expose port
EXPOSE 8082

# Command to run the executable
CMD ["./dynamic-zones"]