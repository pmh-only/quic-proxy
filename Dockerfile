# C++ proxy build stage
FROM ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    g++ \
    libssl-dev \
    zlib1g-dev \
    libbrotli-dev \
    libzstd-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Create build directory
WORKDIR /build

# Copy source files
COPY *.cpp *.h Makefile ./

# Build the application
RUN make clean && make -j$(nproc)

# Production stage
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    zlib1g \
    libbrotli1 \
    libzstd1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && update-ca-certificates

# Create non-root user
RUN groupadd -r proxy && useradd -r -g proxy -s /bin/false proxy

# Create necessary directories
RUN mkdir -p /etc/ssl/certs /etc/ssl/private \
    && chown -R proxy:proxy /etc/ssl

# Copy binary from builder stage
COPY --from=builder /build/quic-proxy /usr/local/bin/quic-proxy
RUN chmod +x /usr/local/bin/quic-proxy

# Set up configuration
ENV BACKEND_HOST=127.0.0.1
ENV BACKEND_PORT=8080
ENV HTTP_PORT=80
ENV HTTPS_PORT=443
ENV TLS_CERT_FILE=/etc/ssl/certs/server.crt
ENV TLS_KEY_FILE=/etc/ssl/private/server.key

# WAF Configuration - for Kubernetes, this will point to WAF service
ENV WAF_ENABLED=true
ENV WAF_HOST=coraza-waf-service
ENV WAF_PORT=9000
ENV WAF_TIMEOUT_MS=1000

# Expose ports
EXPOSE 80 443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/_gwhealthz || exit 1

# Switch to non-root user (commented out as ports 80/443 require root)
# USER proxy

# Start the proxy
CMD ["/usr/local/bin/quic-proxy"]