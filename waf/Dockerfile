# Coraza WAF Service Dockerfile for Kubernetes
FROM golang:1.21-alpine AS builder

# Install required packages
RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o waf-service .

# Final stage
FROM scratch

# Copy CA certificates for HTTPS requests
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary
COPY --from=builder /app/waf-service /waf-service

# Expose the service port
EXPOSE 9000

# Set default environment variables
ENV WAF_PORT=9000
ENV GIN_MODE=release

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/waf-service", "--health-check"] || exit 1

# Run the service
CMD ["/waf-service"]