# 🚀 QUIC Proxy with Coraza WAF

[![Build Status](https://img.shields.io/github/actions/workflow/status/pmh-only/quic-proxy/build-and-push.yml?branch=main)](https://github.com/pmh-only/quic-proxy/actions)
[![Release](https://img.shields.io/github/v/release/pmh-only/quic-proxy)](https://github.com/pmh-only/quic-proxy/releases)
[![License](https://img.shields.io/github/license/pmh-only/quic-proxy)](LICENSE)
[![Kubernetes](https://img.shields.io/badge/kubernetes-1.20+-blue)](https://kubernetes.io)

High-performance C++ reverse proxy with integrated Coraza WAF and OWASP Core Rule Set support, designed for cloud-native deployments.

## ✨ Features

- 🛡️ **Coraza WAF** with OWASP Core Rule Set v4 protection
- ⚡ **Multi-protocol**: HTTP/1.1, HTTP/2, HTTP/3 (QUIC), WebSockets
- 🔒 **Modern TLS**: TLS 1.2/1.3 with restricted cipher suites and ECH support
- 📦 **Advanced Compression**: gzip, brotli, zstd, deflate with intelligent content detection
- ☸️ **Kubernetes-native** with Helm charts and operators
- 🔄 **High Availability** with pod disruption budgets and health checks
- 📊 **Observability** with comprehensive logging and metrics
- 🎯 **Security**: Rate limiting, IP allowlisting, and attack prevention

## 🏗️ Architecture

The proxy consists of two main components that can run as separate containers:

- **QUIC Proxy**: C++ reverse proxy handling client connections
- **Coraza WAF**: Go-based WAF service with OWASP Core Rule Set

## 🚀 Quick Start

### Using Helm (Recommended)

```bash
# Add the Helm repository
helm repo add quic-proxy https://pmh-only.github.io/quic-proxy/charts
helm repo update

# Create namespace and TLS secret
kubectl create namespace quic-proxy
kubectl create secret tls tls-certificate \
  --cert=cert.pem --key=key.pem -n quic-proxy

# Install with your backend configuration
helm install my-proxy quic-proxy/quic-proxy-waf \
  --namespace quic-proxy \
  --set proxy.backend.host=my-backend-service \
  --set proxy.backend.port=8080
```

### Using Kubernetes Manifests

```bash
# Clone the repository
git clone https://github.com/pmh-only/quic-proxy.git
cd quic-proxy

# Deploy using kubectl
kubectl apply -f k8s/
```

### Using Docker

```bash
# Build images locally
./build-images.sh

# Or pull from GitHub Container Registry
docker pull ghcr.io/pmh-only/quic-proxy/quic-proxy:v1.2.3
docker pull ghcr.io/pmh-only/quic-proxy/coraza-waf:v1.2.3
```

## 🔧 Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BACKEND_HOST` | `127.0.0.1` | Backend service hostname |
| `BACKEND_PORT` | `8080` | Backend service port |
| `HTTP_PORT` | `80` | HTTP listen port |
| `HTTPS_PORT` | `443` | HTTPS listen port |
| `WAF_ENABLED` | `true` | Enable/disable WAF protection |
| `WAF_HOST` | `coraza-waf-service` | WAF service hostname |
| `WAF_PORT` | `9000` | WAF service port |
| `WAF_TIMEOUT_MS` | `1000` | WAF request timeout |
| `TLS_CERT_FILE` | `/etc/ssl/certs/server.crt` | TLS certificate file path |
| `TLS_KEY_FILE` | `/etc/ssl/private/server.key` | TLS private key file path |

### Helm Values

```yaml
# values.yaml
proxy:
  replicaCount: 3
  backend:
    host: "my-backend"
    port: 8080

waf:
  enabled: true
  replicaCount: 2

service:
  type: LoadBalancer
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
```

## 🛡️ Security Features

### WAF Protection (OWASP CRS v4)

- ✅ SQL Injection detection and blocking
- ✅ Cross-Site Scripting (XSS) prevention  
- ✅ Path Traversal protection
- ✅ Command Injection blocking
- ✅ Rate limiting (100 req/min per IP)
- ✅ Bot detection and blocking
- ✅ Protocol anomaly detection

### TLS Security

- ✅ TLS 1.2/1.3 only with restricted cipher suites:
  - TLS 1.2: `ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305`
  - TLS 1.3: `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256`
- ✅ Perfect Forward Secrecy with secp384r1 ECDH curve only
- ✅ TLS Early Data support for TLS 1.3 performance
- ✅ ECH (Encrypted Client Hello) when available

### Content Security

- ✅ Automatic X-Forwarded-For (XFF) header calculation (ignores client headers)
- ✅ HTTP to HTTPS redirection on port 80
- ✅ Secure WebSocket proxy functionality
- ✅ Content compression with type detection

## 🐳 Container Images

Images are automatically built and published to GitHub Container Registry:

- **Proxy**: `ghcr.io/pmh-only/quic-proxy/quic-proxy:v1.2.3`
- **WAF**: `ghcr.io/pmh-only/quic-proxy/coraza-waf:v1.2.3`

Multi-architecture support: `linux/amd64`, `linux/arm64`

## 📊 Monitoring

### Health Endpoints

- **Proxy**: `GET /_gwhealthz`
- **WAF**: `GET /health`

### Metrics & Logging

```bash
# View proxy logs
kubectl logs -f deployment/quic-proxy -n quic-proxy

# View WAF logs and blocked requests
kubectl logs -f deployment/coraza-waf -n quic-proxy

# Monitor blocked requests
kubectl logs -f deployment/quic-proxy -n quic-proxy | grep "WAF BLOCKED"
```

## 🔨 Development

### Prerequisites

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev zlib1g-dev libbrotli-dev libzstd-dev pkg-config
```

#### CentOS/RHEL/Rocky Linux
```bash
sudo yum install -y gcc-c++ openssl-devel zlib-devel brotli-devel libzstd-devel pkgconfig
```

#### macOS
```bash
brew install openssl zlib brotli zstd
```

### Building Locally

```bash
# Build C++ proxy
make clean && make -j$(nproc)

# Build WAF service
cd waf && go build .

# Build both services
make all-services

# Run integration tests
./test-waf.sh
```

### Building Images

```bash
# Build both images
./build-images.sh

# Or build with custom registry
REGISTRY=my-registry.com/project ./build-images.sh

# Push to registry
REGISTRY=my-registry.com/project PUSH=true ./build-images.sh
```

### Code Quality

```bash
# Format code
make format

# Run linting
make lint

# Security scanning
make security-scan
```

## 📚 Documentation

- [Kubernetes Deployment Guide](k8s/README.md)
- [Helm Chart Documentation](helm/README.md)
- [Configuration Reference](CLAUDE.md)
- [Security Best Practices](#security-features)
- [Performance Tuning](#performance)

## 🎯 Performance

- **High throughput**: Optimized C++ with asynchronous I/O using ASIO
- **Low latency**: Minimal WAF evaluation overhead (~1-2ms)
- **Horizontal scaling**: Independent proxy and WAF pod scaling
- **Connection efficiency**: Backend connection per request (no pooling for simplicity)
- **Compression**: Automatic content compression for supported types:
  - `text/plain`, `text/css`, `text/xml`
  - `application/xml`, `application/json`, `application/javascript`
  - `text/javascript`, `application/manifest+json`
  - `application/rss+xml`, `image/svg+xml`

## 🚀 Deployment Options

### 1. Kubernetes with Helm
```bash
helm install my-proxy quic-proxy/quic-proxy-waf -n quic-proxy
```

### 2. Kubernetes with Kustomize
```bash
kubectl apply -k k8s/
```

### 3. Docker Compose
```yaml
version: '3.8'
services:
  waf:
    image: ghcr.io/pmh-only/quic-proxy/coraza-waf:v1.2.3
    ports:
      - "9000:9000"
  
  proxy:
    image: ghcr.io/pmh-only/quic-proxy/quic-proxy:v1.2.3
    ports:
      - "80:80"
      - "443:443"
    environment:
      - BACKEND_HOST=backend-service
      - WAF_HOST=waf
    depends_on:
      - waf
```

### 4. Direct Installation
```bash
# Build and install
make clean && make -j$(nproc)
sudo make install

# Configure as systemd service
sudo systemctl enable quic-proxy
sudo systemctl start quic-proxy
```

## 🧪 Testing

### Basic Connectivity
```bash
# Test HTTP (redirects to HTTPS)
curl -i http://localhost/

# Test HTTPS
curl -k -i https://localhost/

# Test health endpoint
curl http://localhost/_gwhealthz
```

### WAF Testing
```bash
# Test legitimate request (should pass)
curl -k https://localhost/api/users

# Test SQL injection (should be blocked)
curl -k "https://localhost/api/users?id=1' OR 1=1--"

# Test XSS (should be blocked)
curl -k -X POST https://localhost/api/comments \
  -d "comment=<script>alert('xss')</script>"
```

### WebSocket Testing
```bash
# Using websocat
websocat wss://localhost/websocket

# Or using wscat
wscat -c wss://localhost/websocket
```

### Compression Testing
```bash
# Test compression
curl -k -H "Accept-Encoding: gzip,br,zstd" https://localhost/api/data
```

## 🛠️ Support & Contributing

### Support
- **Issues**: [GitHub Issues](https://github.com/pmh-only/quic-proxy/issues)
- **Discussions**: [GitHub Discussions](https://github.com/pmh-only/quic-proxy/discussions)
- **Security**: Email security@pmh.codes for security vulnerabilities

### Contributing
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and add tests
4. Run quality checks: `make lint && make test`
5. Commit your changes: `git commit -m 'Add amazing feature'`
6. Push to the branch: `git push origin feature/amazing-feature`
7. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Coraza WAF](https://coraza.io) for the excellent WAF engine
- [OWASP Core Rule Set](https://coreruleset.org) for comprehensive attack protection
- [OpenSSL](https://openssl.org) for cryptographic functions
- [ASIO](https://think-async.com/Asio/) for asynchronous networking

---

Made with ❤️ by [pmh-only](https://github.com/pmh-only)
