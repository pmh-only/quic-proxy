# C++ proxy build stage - Always supports HTTP/3 and ECH
FROM ubuntu:24.04 AS builder

# Install build dependencies including HTTP/3 and ECH support
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    g++ \
    libssl-dev \
    zlib1g-dev \
    libbrotli-dev \
    libzstd-dev \
    libasio-dev \
    libnghttp2-dev \
    pkg-config \
    git \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install autotools for building nghttp3
RUN apt-get update && apt-get install -y \
    autoconf \
    automake \
    libtool \
    autotools-dev \
    && rm -rf /var/lib/apt/lists/*

# Build and install nghttp3 for HTTP/3 support
RUN cd /tmp && \
    git clone --depth 1 https://github.com/ngtcp2/nghttp3.git && \
    cd nghttp3 && \
    git submodule update --init && \
    autoreconf -i && \
    ./configure --enable-lib-only && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    cd / && rm -rf /tmp/nghttp3

# Ensure OpenSSL 3.0+ is available for ECH support
RUN openssl version

# Create build directory
WORKDIR /build

# Copy source files
COPY *.cpp *.h Makefile ./

# Build the application
RUN make clean && make -j$(nproc)

# Production stage - Always supports HTTP/3 and ECH
FROM ubuntu:24.04

# Install runtime dependencies including HTTP/3 and ECH support
RUN apt-get update && apt-get install -y \
    libssl3 \
    zlib1g \
    libbrotli1 \
    libzstd1 \
    libnghttp2-14 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && update-ca-certificates

# Copy nghttp3 runtime library from builder
COPY --from=builder /usr/local/lib/libnghttp3* /usr/local/lib/
RUN ldconfig

# Create necessary directories first
RUN mkdir -p /etc/ssl/certs /etc/ssl/private

# Create non-root user (commented out as proxy needs root for ports 80/443)
# RUN groupadd -r proxy && useradd -r -g proxy -s /bin/false proxy \
#     && chown -R proxy:proxy /etc/ssl

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

# Expose ports - HTTP, HTTPS, and HTTP/3 (QUIC)
EXPOSE 80 443 443/udp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/_gwhealthz || exit 1

# Run as root (required for binding to ports 80/443)

# Start the proxy
CMD ["/usr/local/bin/quic-proxy"]