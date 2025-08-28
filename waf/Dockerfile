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

# Final stage - use alpine instead of scratch for health check
FROM alpine:latest

# Install wget for health checks
RUN apk --no-cache add wget ca-certificates

# Copy CA certificates for HTTPS requests
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary
COPY --from=builder /app/waf-service /waf-service

# Use existing nobody user (more standard and avoids conflicts)
# RUN addgroup -g 10001 -S waf && adduser -u 10001 -S -G waf -H waf

# Expose the service port
EXPOSE 9000

# Set default environment variables
ENV WAF_PORT=9000
ENV GIN_MODE=release

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:9000/health || exit 1

# Switch to nobody user (UID 65534)
USER nobody

# Run the service
CMD ["/waf-service"]